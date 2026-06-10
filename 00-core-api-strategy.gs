/**
 * Clase Base (Protocolo) para cualquier endpoint de Google API.
 * Identifica dinámicamente las columnas y busca por ID.
 * Referencia: Exponential Backoff (https://cloud.google.com/iot/docs/how-tos/exponential-backoff)
 */
class ApiStrategy {
  constructor(name, metricasConfig = []) {
    this.name = name;
    this.metricasConfig = metricasConfig; 
    this.authHeader = null; 
  }

  setAuthHeader(header) {
    this.authHeader = header;
  }

  getRequestConfig() {
    throw new Error("Método getRequestConfig() debe ser implementado");
  }

  parseResponse(jsonResponse, globalContext = null) {
    throw new Error("Método parseResponse() debe ser implementado");
  }

  // PASO 1 y 3: Adaptador de red DRY con Retroceso Exponencial y Jitter
  fetchWithBackoff(url, options, maxRetries = 5) {
    let retries = 0;
    options.muteHttpExceptions = true; 

    while (retries < maxRetries) {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      
      if (code === 429 || code >= 500) {
        retries++;
        const sleepTime = Math.pow(2, retries) * 1000 + Math.floor(Math.random() * 500);
        Logger.log(`[RETRY 429] Red saturada en ${this.name}. Backoff de ${sleepTime}ms (Intento ${retries}/${maxRetries})`);
        Utilities.sleep(sleepTime);
      } else {
        return response; 
      }
    }
    throw new Error(`[CRÍTICO] Fallo de red irrecuperable (HTTP ${code}) tras ${maxRetries} intentos en ${this.name}`);
  }

  fetchPaginated(urlBase, arrayKey) {
    if (!this.authHeader) throw new Error(`[CRÍTICO] No authHeader en ${this.name}`);

    let resultList = [];
    let nextPageToken = "";

    do {
      let url = urlBase;
      if (nextPageToken) url += (url.includes("?") ? "&" : "?") + "pageToken=" + nextPageToken;
      url += (url.includes("?") ? "&" : "?") + "t=" + new Date().getTime();
      let options = { method: "get", headers: this.authHeader };

      try {
        // Unificación DRY: Se invoca fetchWithBackoff en lugar de reescribir el bucle de reintentos
        let response = this.fetchWithBackoff(url, options);
        let json = JSON.parse(response.getContentText());

        if (json.error) {
          Logger.log(`[ERROR API INTERNO] ${urlBase}: ${json.error.message}`);
          return null; 
        }

        let items = json[arrayKey] || [];
        resultList = resultList.concat(items);
        nextPageToken = json.nextPageToken || "";

      } catch (e) {
        Logger.log(`[FALLO DE RED] Excepción en paginación: ${e.message}`);
        return null;
      }
    } while (nextPageToken);

    return resultList;
  }

  // PASO 5: Optimización de Hojas de Cálculo. Volcado masivo O(1) en red.
  writeToSheet(res) {
    if (!this.metricasConfig || this.metricasConfig.length === 0) return;

    const sheetName = "Google Workspace Configuraciones de Seguridad";
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(sheetName);
    if (!sheet) return;

    const dataRange = sheet.getDataRange();
    const values = dataRange.getValues();
    const headers = values[1]; // Fila 2 index 1

    let colId = -1, colSetting = -1, colNotes = -1, colRisk = -1, colTime = -1;

    headers.forEach((header, index) => {
      const h = header.toString().toLowerCase().trim();
      if (h === 'id' || h === 'd') colId = index;
      else if (h.includes('setting') || h.includes('configuración')) colSetting = index;
      else if (h.includes('note') || h.includes('nota')) colNotes = index;
      else if (h.includes('level of risk') || h.includes('riesgo')) colRisk = index;
      else if (h.includes('timestamp') || h.includes('fecha')) colTime = index;
    });

    if (colId === -1 || colSetting === -1) return;

    const timestamp = Utilities.formatDate(new Date(), "America/Bogota", "yyyy-MM-dd HH:mm:ss");
    let needsUpdate = false;

    this.metricasConfig.forEach(metrica => {
      for (let i = 2; i < values.length; i++) {
        if (values[i][colId] && values[i][colId].toString().trim() === metrica.id) {
          if (metrica.valueKey && res[metrica.valueKey] !== undefined) values[i][colSetting] = res[metrica.valueKey];
          if (colNotes !== -1 && metrica.noteKey && res[metrica.noteKey] !== undefined) values[i][colNotes] = res[metrica.noteKey];
          if (colRisk !== -1 && metrica.riskKey && res[metrica.riskKey] !== undefined) values[i][colRisk] = res[metrica.riskKey];
          if (colTime !== -1) values[i][colTime] = timestamp;
          
          needsUpdate = true;
          if (metrica.scoreKey && res[metrica.scoreKey] !== undefined) {
            this.writeScoreToSheet(SpreadsheetApp.getActiveSpreadsheet(), metrica.id, res[metrica.scoreKey]);
          }
          break;
        }
      }
    });

    // Operación I/O atómica
    if (needsUpdate) dataRange.setValues(values);
  }

  writeScoreToSheet(spreadsheet, metricaId, scoreValue) {
    const scoreSheet = spreadsheet.getSheetByName("Scores");
    if (!scoreSheet) return;

    const dataRange = scoreSheet.getDataRange();
    const values = dataRange.getValues();
    const headers = values[0];
    let colIdentity = -1;

    headers.forEach((h, i) => {
      if (h.toString().toLowerCase().trim().includes('level of risks identity')) colIdentity = i;
    });

    if (colIdentity !== -1) {
      let found = false;
      for (let i = 1; i < values.length; i++) {
        if (values[i][colIdentity] && values[i][colIdentity].toString().trim() === metricaId) {
          values[i][colIdentity + 1] = scoreValue;
          found = true;
          break;
        }
      }

      if (!found) {
        let newRow = new Array(headers.length).fill("");
        newRow[colIdentity] = metricaId;
        newRow[colIdentity + 1] = scoreValue;
        values.push(newRow);
      }
      
      scoreSheet.getRange(1, 1, values.length, values[0].length).setValues(values);
    }
  }
}