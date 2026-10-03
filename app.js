    'use strict';

    const APP_NAME = 'auditable-group-draw';
    const APP_VERSION = '0.2.0';
    const CONFIG_SCHEMA_VERSION = '2';
    const AUDIT_SCHEMA_VERSION = '2';
    const ALGORITHM = 'enumerate-valid-assignments-sha256-seed-v1';
    const MAX_ENUMERABLE = 20;
    const MAX_NAME_LENGTH = 200;
    const MAX_NAMES_INPUT_LENGTH = 5000;
    const MAX_CONSTRAINT_INPUT_LENGTH = 20000;
    const MAX_TURN_NAME_LENGTH = 100;
    const MAX_SEED_LENGTH = 4096;
    const FORBIDDEN_NAME_SEPARATORS = /[+,;|]/;
    const UNSAFE_INVISIBLE = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/;
    const $ = (id) => document.getElementById(id);

    let preparedNames = null;
    let committed = null;
    let lastAuditObject = null;

    function normalizeText(value) {
      return String(value).trim().normalize('NFC');
    }

    function nameKey(value) {
      return normalizeText(value).toLowerCase();
    }

    function assertSafeText(value, label, maxLength) {
      const text = normalizeText(value);
      if (!text) throw new Error(`${label} no puede estar vacío.`);
      if (text.length > maxLength) throw new Error(`${label} supera el máximo de ${maxLength} caracteres.`);
      if (UNSAFE_INVISIBLE.test(text)) throw new Error(`${label} contiene caracteres de control o formato invisible no permitidos.`);
      return text;
    }

    function assertSafeParticipantName(value) {
      const text = assertSafeText(value, 'El nombre de participante', MAX_NAME_LENGTH);
      if (FORBIDDEN_NAME_SEPARATORS.test(text)) {
        throw new Error(`El nombre “${text}” contiene uno de los separadores reservados para restricciones: + , ; |`);
      }
      return text;
    }

    function parseCapacity(raw, label) {
      const text = normalizeText(raw);
      if (!/^\d+$/.test(text)) throw new Error(`${label} debe ser un entero entre 0 y ${MAX_ENUMERABLE}.`);
      const value = Number(text);
      if (!Number.isSafeInteger(value) || value < 0 || value > MAX_ENUMERABLE) {
        throw new Error(`${label} debe ser un entero entre 0 y ${MAX_ENUMERABLE}.`);
      }
      return value;
    }

    function trimLines(text) {
      return text.split(/\r?\n/).map(normalizeText).filter(Boolean);
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>\"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[ch]));
    }

    function arraysEqual(a, b) {
      return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => v === b[i]);
    }

    function hex(buffer) {
      return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function ensureCryptoSupport() {
      const cryptoApi = globalThis.crypto;
      if (!cryptoApi || !cryptoApi.subtle || !cryptoApi.getRandomValues || !globalThis.TextEncoder || typeof BigInt !== 'function') {
        throw new Error('Este entorno no ofrece las primitivas criptográficas necesarias. Usa una versión actual de Firefox, Chromium, Chrome, Edge, Safari o Node.js.');
      }
    }

    async function sha256Hex(text) {
      ensureCryptoSupport();
      const enc = new TextEncoder();
      const digest = await globalThis.crypto.subtle.digest('SHA-256', enc.encode(text));
      return hex(digest);
    }

    function canonicalJson(obj) {
      if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
      if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
      return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
    }

    function setAuditButtonsEnabled(enabled) {
      $('copyAuditBtn').disabled = !enabled;
      $('downloadAuditBtn').disabled = !enabled;
      $('downloadJsonBtn').disabled = !enabled;
    }

    function clearResult(message = '') {
      lastAuditObject = null;
      $('result').classList.add('hidden');
      $('listTurn1').innerHTML = '';
      $('listTurn2').innerHTML = '';
      $('audit').value = 'El acta aparecerá aquí tras realizar el sorteo.';
      setAuditButtonsEnabled(false);
      if (message) {
        $('drawStatus').className = 'status warn';
        $('drawStatus').textContent = message;
      } else {
        $('drawStatus').textContent = '';
        $('drawStatus').className = 'status';
      }
    }

    function refreshSeedControls() {
      const ready = Boolean(committed);
      $('seed').disabled = !ready;
      $('randomSeedBtn').disabled = !ready;
      $('copyConfigBtn').disabled = !ready;
      $('drawBtn').disabled = !ready || !normalizeText($('seed').value);
      $('seed').placeholder = ready ? 'Semilla pública generada después de fijar la configuración' : 'Primero fija la configuración';
    }

    function invalidateCommitment(reason, forceAnnouncement = false) {
      const hadCommit = Boolean(committed);
      committed = null;
      $('configHash').textContent = '—';
      $('seed').value = '';
      clearResult();
      refreshSeedControls();
      if (hadCommit || forceAnnouncement) {
        $('validationStatus').className = 'status warn';
        $('validationStatus').textContent = reason || 'La configuración ha cambiado. Vuelve a validarla y fijarla antes de generar una nueva semilla.';
      } else {
        $('validationStatus').textContent = '';
        $('validationStatus').className = 'status';
      }
    }

    function parseNamesText(text) {
      const raw = String(text);
      if (raw.length > MAX_NAMES_INPUT_LENGTH) throw new Error(`La lista de participantes supera el máximo de ${MAX_NAMES_INPUT_LENGTH} caracteres.`);
      const names = trimLines(raw).map(assertSafeParticipantName);
      const seen = new Map();
      const dup = [];
      names.forEach((name, idx) => {
        const key = nameKey(name);
        if (seen.has(key)) dup.push(name);
        seen.set(key, idx);
      });
      if (dup.length) throw new Error('Hay nombres duplicados o indistinguibles: ' + dup.join(', '));
      if (names.length < 2) throw new Error('Introduce al menos dos participantes.');
      if (names.length > MAX_ENUMERABLE) throw new Error(`Esta versión enumera hasta ${MAX_ENUMERABLE} participantes. Para grupos mayores conviene usar otro método de resolución.`);
      return names;
    }

    function getNames() {
      return parseNamesText($('names').value);
    }

    function nameIndexMap(names) {
      const map = new Map();
      names.forEach((name, i) => map.set(nameKey(name), i));
      return map;
    }

    function splitConstraintLine(line) {
      return line.split(/\s*(?:\+|,|;|\|)\s*/).map(normalizeText).filter(Boolean);
    }

    function compareNumberArrays(a, b) {
      const n = Math.min(a.length, b.length);
      for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
      }
      return a.length - b.length;
    }

    function parseGroups(text, names, label) {
      if (String(text).length > MAX_CONSTRAINT_INPUT_LENGTH) throw new Error(`${label}: el texto supera el máximo de ${MAX_CONSTRAINT_INPUT_LENGTH} caracteres.`);
      const idx = nameIndexMap(names);
      const groupsByKey = new Map();
      const errors = [];
      trimLines(text).forEach((line, n) => {
        const parts = splitConstraintLine(line);
        if (parts.length < 2) {
          errors.push(`${label}, línea ${n + 1}: debe contener al menos dos nombres.`);
          return;
        }
        const rawIndices = [];
        let hasUnknown = false;
        for (const raw of parts) {
          const key = nameKey(raw);
          if (!idx.has(key)) {
            hasUnknown = true;
            errors.push(`${label}, línea ${n + 1}: “${raw}” no está en la lista de participantes.`);
          } else {
            rawIndices.push(idx.get(key));
          }
        }
        const group = [...new Set(rawIndices)].sort((a, b) => a - b);
        if (!hasUnknown && rawIndices.length && group.length < 2) {
          errors.push(`${label}, línea ${n + 1}: repite la misma persona; deben aparecer al menos dos personas distintas.`);
          return;
        }
        if (group.length >= 2) groupsByKey.set(group.join(','), group);
      });
      if (errors.length) throw new Error(errors.join('\n'));
      return [...groupsByKey.values()].sort(compareNumberArrays);
    }

    function syncFixedTurnLabels() {
      const t1 = normalizeText($('turn1Name').value) || 'Turno 1';
      const t2 = normalizeText($('turn2Name').value) || 'Turno 2';
      document.querySelectorAll('select[data-fixed-index]').forEach(sel => {
        const o1 = [...sel.options].find(o => o.value === 'T1');
        const o2 = [...sel.options].find(o => o.value === 'T2');
        if (o1) o1.textContent = t1;
        if (o2) o2.textContent = t2;
      });
    }

    function prepareRestrictions() {
      const names = getNames();
      preparedNames = names.slice();
      const t1 = normalizeText($('turn1Name').value) || 'Turno 1';
      const t2 = normalizeText($('turn2Name').value) || 'Turno 2';
      let rows = `<table class="participants-table"><thead><tr><th>#</th><th>Persona</th><th>Restricción de turno</th></tr></thead><tbody>`;
      names.forEach((name, i) => {
        rows += `<tr><td>${i + 1}</td><td class="participant-name">${escapeHtml(name)}</td><td><select data-fixed-index="${i}" aria-label="Restricción de turno para ${escapeHtml(name)}">
          <option value="any">Cualquiera</option>
          <option value="T1">${escapeHtml(t1)}</option>
          <option value="T2">${escapeHtml(t2)}</option>
        </select></td></tr>`;
      });
      rows += '</tbody></table>';
      $('fixedContainer').className = '';
      $('fixedContainer').innerHTML = rows;
      document.querySelectorAll('select[data-fixed-index]').forEach(sel => {
        sel.addEventListener('change', () => invalidateCommitment('Has cambiado una restricción individual. Vuelve a validar y fijar la configuración.'));
      });
      $('prepareStatus').className = 'status ok';
      $('prepareStatus').textContent = `Preparadas ${names.length} personas. Ya puedes marcar turnos obligatorios y fijar la configuración.`;
      invalidateCommitment('', false);
    }

    function getFixed(names) {
      const selects = [...document.querySelectorAll('select[data-fixed-index]')];
      if (!arraysEqual(preparedNames, names) || selects.length !== names.length) {
        throw new Error('La tabla de restricciones individuales no corresponde exactamente a la lista actual. Pulsa “Preparar restricciones” antes de continuar.');
      }
      const fixed = Array(names.length).fill(null);
      selects.forEach((sel, expectedIndex) => {
        const i = Number(sel.dataset.fixedIndex);
        if (!Number.isInteger(i) || i !== expectedIndex || i < 0 || i >= names.length) {
          throw new Error('La tabla de restricciones individuales tiene un estado incoherente. Vuelve a prepararla.');
        }
        if (!['any', 'T1', 'T2'].includes(sel.value)) {
          throw new Error('La tabla de restricciones individuales contiene un valor no permitido. Vuelve a prepararla.');
        }
        fixed[i] = sel.value === 'any' ? null : sel.value;
      });
      return fixed;
    }

    function buildConfig() {
      const names = getNames();
      const turn1Name = assertSafeText($('turn1Name').value, 'El nombre del turno 1', MAX_TURN_NAME_LENGTH);
      const turn2Name = assertSafeText($('turn2Name').value, 'El nombre del turno 2', MAX_TURN_NAME_LENGTH);
      if (nameKey(turn1Name) === nameKey(turn2Name)) throw new Error('Los dos turnos deben tener nombres distintos.');

      const cap1 = parseCapacity($('cap1').value, 'El máximo del turno 1');
      const cap2 = parseCapacity($('cap2').value, 'El máximo del turno 2');
      if (names.length > cap1 + cap2) {
        throw new Error(`Capacidad insuficiente: hay ${names.length} personas y solo ${cap1 + cap2} plazas entre los dos turnos.`);
      }

      const fixed = getFixed(names);
      const together = parseGroups($('together').value, names, 'Deben ir juntas/os');
      const apart = parseGroups($('apart').value, names, 'No deben coincidir');
      for (const g of apart) {
        if (g.length > 2) {
          throw new Error(`Restricción imposible en “No deben coincidir”: ${g.map(i => names[i]).join(', ')}. Con dos turnos no se puede separar entre sí a tres o más personas.`);
        }
      }

      return {
        schemaVersion: CONFIG_SCHEMA_VERSION,
        algorithm: ALGORITHM,
        names,
        turnNames: [turn1Name, turn2Name],
        capacities: [cap1, cap2],
        fixed,
        together,
        apart
      };
    }

    function bit(mask, i) {
      return (mask >> i) & 1;
    }

    function popcount(mask) {
      let c = 0;
      while (mask) { mask &= mask - 1; c++; }
      return c;
    }

    function validMask(mask, config) {
      const n = config.names.length;
      const size1 = popcount(mask);
      const size2 = n - size1;
      if (size1 > config.capacities[0] || size2 > config.capacities[1]) return false;
      for (let i = 0; i < n; i++) {
        if (config.fixed[i] === 'T1' && bit(mask, i) !== 1) return false;
        if (config.fixed[i] === 'T2' && bit(mask, i) !== 0) return false;
      }
      for (const group of config.together) {
        const b = bit(mask, group[0]);
        for (const i of group) if (bit(mask, i) !== b) return false;
      }
      for (const group of config.apart) {
        if (bit(mask, group[0]) === bit(mask, group[1])) return false;
      }
      return true;
    }

    function enumerateValid(config) {
      const total = 2 ** config.names.length;
      const valid = [];
      for (let mask = 0; mask < total; mask++) {
        if (validMask(mask, config)) valid.push(mask);
      }
      return valid;
    }

    function assignmentFromMask(mask, names) {
      const t1 = [];
      const t2 = [];
      names.forEach((name, i) => bit(mask, i) ? t1.push(name) : t2.push(name));
      return [t1, t2];
    }

    function participantBits(mask, names) {
      return names.map((name, i) => ({ position: i, name, bit: bit(mask, i) }));
    }

    function summarizeConstraints(config) {
      const lines = [];
      config.fixed.forEach((f, i) => {
        if (f === 'T1') lines.push(`- ${config.names[i]} debe ir a ${config.turnNames[0]}`);
        if (f === 'T2') lines.push(`- ${config.names[i]} debe ir a ${config.turnNames[1]}`);
      });
      config.together.forEach(g => lines.push(`- Juntos/as: ${g.map(i => config.names[i]).join(' + ')}`));
      config.apart.forEach(g => lines.push(`- Separados/as: ${g.map(i => config.names[i]).join(' + ')}`));
      return lines.length ? lines.join('\n') : '- Sin restricciones adicionales';
    }

    async function validateAndCommit() {
      ensureCryptoSupport();
      const config = buildConfig();
      const normalized = canonicalJson(config);
      const configHash = await sha256Hex(normalized);
      const valid = enumerateValid(config);
      if (!valid.length) throw new Error('No existe ningún reparto que cumpla todas las restricciones.');

      committed = { config, normalized, configHash, valid };
      $('configHash').textContent = configHash;
      $('seed').value = '';
      clearResult();
      refreshSeedControls();

      const n = config.names.length;
      const deterministic = valid.length === 1;
      $('validationStatus').className = deterministic ? 'status warn' : 'status ok';
      $('validationStatus').textContent = `Configuración validada y fijada.\nPersonas: ${n}. Repartos examinados: ${2 ** n}. Repartos válidos: ${valid.length}.\nHuella comprometida: ${configHash}\n${deterministic ? 'Las restricciones determinan un único reparto: la semilla no puede cambiar el resultado.' : 'La semilla ya está habilitada. Genérala o introdúcela después de registrar esta huella.'}`;
      return committed;
    }

    function assertCommitStillMatches() {
      if (!committed) throw new Error('Primero valida y fija la configuración.');
      let currentNormalized;
      try {
        currentNormalized = canonicalJson(buildConfig());
      } catch (err) {
        invalidateCommitment('La configuración ya no coincide con la que se fijó. Vuelve a prepararla y validarla.', true);
        throw err;
      }
      if (currentNormalized !== committed.normalized) {
        invalidateCommitment('La configuración ha cambiado después de fijarse. La semilla y cualquier resultado anterior han sido invalidados.', true);
        throw new Error('La configuración ha cambiado después de fijarse. Vuelve a validarla antes de sortear.');
      }
      return committed;
    }

    async function chooseIndex(configHash, seed, validCount) {
      const TWO_256 = 1n << 256n;
      const count = BigInt(validCount);
      const limit = (TWO_256 / count) * count;
      let counter = 0;
      while (true) {
        const material = `${configHash}|${seed}|${counter}`;
        const digest = await sha256Hex(material);
        const value = BigInt('0x' + digest);
        if (value < limit) {
          return {
            index: Number(value % count),
            counter,
            digest,
            material,
            rejectionLimitHex: '0x' + limit.toString(16)
          };
        }
        counter++;
      }
    }

    function renderResult(config, mask) {
      const [t1, t2] = assignmentFromMask(mask, config.names);
      $('resTurn1').textContent = `${config.turnNames[0]} · ${t1.length} persona(s)`;
      $('resTurn2').textContent = `${config.turnNames[1]} · ${t2.length} persona(s)`;
      $('listTurn1').innerHTML = t1.map(n => `<li>${escapeHtml(n)}</li>`).join('');
      $('listTurn2').innerHTML = t2.map(n => `<li>${escapeHtml(n)}</li>`).join('');
      $('result').classList.remove('hidden');
      return [t1, t2];
    }

    function auditText(a) {
      const bitVector = a.participantBits.map(p => p.bit).join(' ');
      return `ACTA DE SORTEO AUDITABLE DE GRUPOS

Fecha/hora local del sorteo: ${a.localDateTime}
Fecha/hora UTC del sorteo:   ${a.utcDateTime}
Aplicación: ${a.app} ${a.appVersion}
Versión de código: ${a.sourceVersion}

PROTOCOLO
- La configuración se valida y se compromete mediante su huella SHA-256 antes de habilitar la semilla.
- Cualquier modificación posterior de participantes, turnos o restricciones invalida el compromiso, la semilla y el resultado.
- Para que el resultado sea impredecible, la semilla debe generarse o revelarse después de fijar la configuración.

MÉTODO
- Se enumeran todos los repartos válidos en orden ascendente de máscara entera.
- La persona en posición 0 usa el bit menos significativo. Bit 1 = ${a.config.turnNames[0]}; bit 0 = ${a.config.turnNames[1]}.
- Se calcula SHA-256(configHash | seed | counter). El primer digest aceptado se transforma en un índice uniforme mediante rejection sampling, evitando sesgo de módulo.

PARTICIPANTES, EN ORDEN CANÓNICO
${a.config.names.map((n, i) => `${String(i + 1).padStart(2, '0')}. ${n}`).join('\n')}

TURNOS Y CAPACIDADES
- ${a.config.turnNames[0]}: máximo ${a.config.capacities[0]}
- ${a.config.turnNames[1]}: máximo ${a.config.capacities[1]}

RESTRICCIONES
${summarizeConstraints(a.config)}

CONFIGURACIÓN NORMALIZADA
${a.normalizedConfig}

HUELLA SHA-256 DE LA CONFIGURACIÓN
${a.configHash}

SEMILLA PÚBLICA
${a.seed}

CÁLCULO DEL ÍNDICE
- Repartos válidos: ${a.validCount}
- Counter usado: ${a.counter}
- Material hasheado: ${a.hashMaterial}
- Digest SHA-256: ${a.selectionDigest}
- Índice seleccionado, base 0: ${a.selectedIndex0}
- Índice seleccionado, base 1: ${a.selectedIndex1}
- Máscara entera seleccionada: ${a.selectedMaskInteger}
- Máscara binaria convencional, bit más significativo a la izquierda: ${a.selectedMaskBinary}
- Bits en orden de participantes, persona 1 a persona ${a.config.names.length}: ${bitVector}

RESULTADO
${a.config.turnNames[0]} (${a.assignment[0].length})
${a.assignment[0].map(n => `- ${n}`).join('\n')}

${a.config.turnNames[1]} (${a.assignment[1].length})
${a.assignment[1].map(n => `- ${n}`).join('\n')}

JSON DE AUDITORÍA
${JSON.stringify(a, null, 2)}
`;
    }

    function download(filename, content, type = 'text/plain;charset=utf-8') {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    async function copyText(text) {
      if (navigator.clipboard && window.isSecureContext) {
        try {
          await navigator.clipboard.writeText(text);
          return;
        } catch (_) {}
      }
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'clipboard-proxy';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      if (!ok) throw new Error('El navegador no ha permitido copiar al portapapeles. Puedes seleccionar y copiar el texto manualmente.');
    }

    function auditFilename(extension) {
      const stamp = lastAuditObject.utcDateTime.replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z').replace('T', '-');
      return `auditable-group-draw-${stamp}-${lastAuditObject.configHash.slice(0, 8)}.${extension}`;
    }


    if (typeof module !== 'undefined' && module.exports) {
      module.exports = {
        ALGORITHM,
        CONFIG_SCHEMA_VERSION,
        AUDIT_SCHEMA_VERSION,
        MAX_ENUMERABLE,
        canonicalJson,
        sha256Hex,
        validMask,
        enumerateValid,
        assignmentFromMask,
        participantBits,
        chooseIndex,
        parseCapacity,
        assertSafeText,
        assertSafeParticipantName,
        parseGroups,
        parseNamesText
      };
    }

    if (typeof document !== 'undefined') {
      $('prepareBtn').addEventListener('click', () => {
        try {
          prepareRestrictions();
        } catch (err) {
          $('prepareStatus').className = 'status err';
          $('prepareStatus').textContent = err.message;
        }
      });

      $('exampleBtn').addEventListener('click', () => {
        $('names').value = `Ana\nBruno\nCarla\nDiego\nElena\nFran\nGema\nHugo\nIrene\nJavi\nLaura\nMarcos`;
        $('turn1Name').value = 'Turno 1';
        $('turn2Name').value = 'Turno 2';
        $('cap1').value = 6;
        $('cap2').value = 6;
        $('together').value = '';
        $('apart').value = '';
        prepareRestrictions();
      });

      $('validateBtn').addEventListener('click', async () => {
        try {
          await validateAndCommit();
        } catch (err) {
          committed = null;
          $('validationStatus').className = 'status err';
          $('validationStatus').textContent = err.message;
          $('configHash').textContent = '—';
          $('seed').value = '';
          clearResult();
          refreshSeedControls();
        }
      });

      $('copyConfigBtn').addEventListener('click', async () => {
        try {
          const c = assertCommitStillMatches();
          await copyText(c.normalized);
          $('validationStatus').className = 'status ok';
          $('validationStatus').textContent = `Configuración comprometida copiada. Huella: ${c.configHash}`;
        } catch (err) {
          $('validationStatus').className = 'status err';
          $('validationStatus').textContent = err.message;
        }
      });

      $('randomSeedBtn').addEventListener('click', () => {
        try {
          assertCommitStillMatches();
          ensureCryptoSupport();
          const bytes = new Uint8Array(32);
          crypto.getRandomValues(bytes);
          $('seed').value = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
          clearResult('Semilla criptográfica generada después del compromiso. Ya puedes realizar el sorteo.');
          refreshSeedControls();
        } catch (err) {
          $('drawStatus').className = 'status err';
          $('drawStatus').textContent = err.message;
        }
      });

      $('seed').addEventListener('input', () => {
        if (lastAuditObject) clearResult('La semilla ha cambiado. El resultado anterior ha sido invalidado.');
        refreshSeedControls();
      });

      $('drawBtn').addEventListener('click', async () => {
        try {
          const c = assertCommitStillMatches();
          const seed = assertSafeText($('seed').value, 'La semilla pública', MAX_SEED_LENGTH);
          const choice = await chooseIndex(c.configHash, seed, c.valid.length);
          const selectedMask = c.valid[choice.index];
          const assignment = renderResult(c.config, selectedMask);
          const now = new Date();
          const audit = {
            auditSchemaVersion: AUDIT_SCHEMA_VERSION,
            app: APP_NAME,
            appVersion: APP_VERSION,
            sourceRepository: 'https://github.com/lpla/auditable-group-draw',
            sourceVersion: `v${APP_VERSION}`,
            localDateTime: now.toLocaleString(),
            utcDateTime: now.toISOString(),
            method: c.config.algorithm,
            config: c.config,
            normalizedConfig: c.normalized,
            configHash: c.configHash,
            seed,
            validCount: c.valid.length,
            selectedIndex0: choice.index,
            selectedIndex1: choice.index + 1,
            selectedMaskInteger: selectedMask,
            selectedMaskBinary: selectedMask.toString(2).padStart(c.config.names.length, '0'),
            participantBits: participantBits(selectedMask, c.config.names),
            counter: choice.counter,
            hashMaterial: choice.material,
            selectionDigest: choice.digest,
            rejectionLimitHex: choice.rejectionLimitHex,
            assignment
          };
          lastAuditObject = audit;
          setAuditButtonsEnabled(true);
          $('drawStatus').className = 'status ok';
          $('drawStatus').textContent = c.valid.length === 1
            ? 'Resultado determinado por las restricciones: existe un único reparto válido. La semilla queda registrada, pero no puede alterar este resultado.'
            : `Sorteo realizado. Se ha seleccionado uniformemente el reparto ${choice.index + 1} de ${c.valid.length} repartos válidos.`;
          $('audit').value = auditText(audit);
        } catch (err) {
          $('drawStatus').className = 'status err';
          $('drawStatus').textContent = err.message;
        }
      });

      $('copyAuditBtn').addEventListener('click', async () => {
        if (!lastAuditObject) return;
        try {
          await copyText($('audit').value);
          $('drawStatus').className = 'status ok';
          $('drawStatus').textContent = 'Acta copiada al portapapeles.';
        } catch (err) {
          $('drawStatus').className = 'status err';
          $('drawStatus').textContent = err.message;
        }
      });

      $('downloadAuditBtn').addEventListener('click', () => {
        if (!lastAuditObject) return;
        download(auditFilename('txt'), $('audit').value);
      });

      $('downloadJsonBtn').addEventListener('click', () => {
        if (!lastAuditObject) return;
        download(auditFilename('json'), JSON.stringify(lastAuditObject, null, 2), 'application/json;charset=utf-8');
      });

      const configInputIds = ['names', 'turn1Name', 'turn2Name', 'cap1', 'cap2', 'together', 'apart'];
      configInputIds.forEach(id => {
        $(id).addEventListener('input', () => {
          const hadCommit = Boolean(committed);
          if (id === 'turn1Name' || id === 'turn2Name') syncFixedTurnLabels();
          if (id === 'names' && preparedNames) {
            try {
              if (!arraysEqual(preparedNames, getNames())) {
                $('prepareStatus').className = 'status warn';
                $('prepareStatus').textContent = 'La lista de participantes ha cambiado. Vuelve a pulsar “Preparar restricciones” para evitar reasignaciones por posición.';
              } else {
                $('prepareStatus').className = 'status ok';
                $('prepareStatus').textContent = `Preparadas ${preparedNames.length} personas. La tabla vuelve a coincidir con la lista actual.`;
              }
            } catch (_) {
              $('prepareStatus').className = 'status warn';
              $('prepareStatus').textContent = 'La lista de participantes ha cambiado. Vuelve a preparar las restricciones cuando sea válida.';
            }
          }
          invalidateCommitment('La configuración se ha modificado. La huella anterior, la semilla y cualquier resultado han sido invalidados.', hadCommit);
        });
      });

      window.addEventListener('load', () => {
        setAuditButtonsEnabled(false);
        refreshSeedControls();
        try {
          ensureCryptoSupport();
          prepareRestrictions();
        } catch (err) {
          $('prepareStatus').className = 'status err';
          $('prepareStatus').textContent = err.message;
          $('validateBtn').disabled = true;
        }
      });
    }
