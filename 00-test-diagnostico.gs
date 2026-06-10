/**
 * Script de diagnóstico forense ajustado para V1.
 */
function diagnosticoPolicyAPI_NivelForense_V1() {
  const auth = new AuthService();
  
  // 1. CONFIGURACIÓN EXACTA
  const adminEmail = "admin@test.apisas.com"; 
  const customerIdString = "customers/C03kl8vnq"; 
  
  // 💡 CAMBIO A V1 SOLICITADO
  const apiVersion = "v1"; 
  
  Logger.log("==================================================================");
  Logger.log(`[FORENSE] INICIANDO DIAGNÓSTICO PROFUNDO`);
  Logger.log(`[FORENSE] Suplantando a Súper Admin: ${adminEmail}`);
  Logger.log(`[FORENSE] Customer ID Objetivo: ${customerIdString}`);
  Logger.log(`[FORENSE] Versión de API en uso: ${apiVersion}`);
  Logger.log("==================================================================");

  // 2. OBTENER TOKEN DWD
  let privilegedHeader;
  try {
    privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
      "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
    ]);
    const tokenParcial = privilegedHeader.Authorization.substring(0, 20) + "...";
    Logger.log(`[FORENSE - AUTH] Token DWD generado con éxito. Bearer: ${tokenParcial}`);
  } catch (e) {
    Logger.log(`[FORENSE - CRÍTICO] Falló la generación del token: ${e.message}`);
    return;
  }

  // ==============================================================================
  // PRUEBA A: DESCARGAR TODO Y FILTRAR MANUALMENTE EN JAVASCRIPT
  // ==============================================================================
  Logger.log("\n--- PRUEBA A: DESCARGA MASIVA (Paginación) ---");
  const filterAll = encodeURIComponent(`customer=="${customerIdString}"`);
  const baseUrlAll = `https://cloudidentity.googleapis.com/${apiVersion}/policies?filter=${filterAll}&pageSize=100`;
  
  let pageToken = "";
  let paginaActual = 0;
  let totalPoliticasDescargadas = 0;
  let politicasSeguridadEncontradas = 0;
  let rawSecurityTypes = new Set();

  do {
    paginaActual++;
    let url = baseUrlAll;
    if (pageToken) url += `&pageToken=${pageToken}`;
    
    Logger.log(`[PRUEBA A] --> Solicitando Página #${paginaActual}...`);
    
    const response = UrlFetchApp.fetch(url, { method: "get", headers: privilegedHeader, muteHttpExceptions: true });
    const code = response.getResponseCode();
    const rawText = response.getContentText();
    
    Logger.log(`[PRUEBA A] <-- Respuesta HTTP ${code} recibida. Peso del payload: ${rawText.length} bytes.`);
    
    if (code !== 200) {
      Logger.log(`[PRUEBA A - ERROR] La API rechazó la petición: ${rawText}`);
      break;
    }

    const json = JSON.parse(rawText);
    const politicasEnPagina = json.policies ? json.policies.length : 0;
    totalPoliticasDescargadas += politicasEnPagina;
    
    Logger.log(`[PRUEBA A] Analizando ${politicasEnPagina} políticas en la página #${paginaActual}...`);

    // Escáner manual interno: CORREGIDO PARA IGNORAR EL PREFIJO "settings/"
    if (json.policies) {
      json.policies.forEach(p => {
        const type = p.setting?.type || "DESCONOCIDO";
        // Usamos includes() para que atrape "settings/security.two_step..."
        if (type.includes("security.")) {
          Logger.log(`[DEBUG - MATCH] Política de seguridad encontrada: ${type}`);
          politicasSeguridadEncontradas++;
          rawSecurityTypes.add(type);
        }
      });
    }

    pageToken = json.nextPageToken;
    if (pageToken) {
      Logger.log(`[PRUEBA A] Hay más resultados. Token de paginación recibido. Esperando 1000ms...`);
      Utilities.sleep(1000);
    } else {
      Logger.log(`[PRUEBA A] Paginación finalizada. No hay más páginas.`);
    }
  } while (pageToken);

  Logger.log(`\n[RESUMEN PRUEBA A]`);
  Logger.log(`* Total páginas procesadas: ${paginaActual}`);
  Logger.log(`* Total políticas puras descargadas: ${totalPoliticasDescargadas}`);
  Logger.log(`* Total políticas detectadas manualmente que incluyen 'security.': ${politicasSeguridadEncontradas}`);
  
  if (politicasSeguridadEncontradas > 0) {
    Logger.log(`* Tipos de seguridad detectados: ${Array.from(rawSecurityTypes).join(", ")}`);
  } else {
    Logger.log(`* CONCLUSIÓN: La API V1 entregó ${totalPoliticasDescargadas} configuraciones, pero NINGUNA es de seguridad. Google no las está enviando a esta cuenta bajo esta versión.`);
  }

  // ==============================================================================
  // PRUEBA B: USAR EL FILTRO DE GOOGLE PARA EXIGIR SOLO SEGURIDAD
  // ==============================================================================
  Logger.log("\n--- PRUEBA B: PETICIÓN CON FILTRO ESTRICTO DE SEGURIDAD ---");
  
  // CORRECCIÓN REGEX: El anterior fallaba porque buscaba explícitamente el inicio de cadena (^).
  // Ahora permite que la cadena contenga "settings/" antes de la palabra "security".
  const filterSec = encodeURIComponent(`setting.type.matches(".*security\\\\..*") && customer=="${customerIdString}"`);
  const urlSec = `https://cloudidentity.googleapis.com/${apiVersion}/policies?filter=${filterSec}`;
  
  Logger.log(`[PRUEBA B] --> Enviando petición con filtro regex estricto...`);
  const responseSec = UrlFetchApp.fetch(urlSec, { method: "get", headers: privilegedHeader, muteHttpExceptions: true });
  
  Logger.log(`[PRUEBA B] <-- HTTP ${responseSec.getResponseCode()}. Peso: ${responseSec.getContentText().length} bytes.`);
  
  const jsonSec = JSON.parse(responseSec.getContentText());
  const totalSec = jsonSec.policies ? jsonSec.policies.length : 0;
  
  Logger.log(`[RESUMEN PRUEBA B] Políticas devueltas por Google usando filtro en V1: ${totalSec}`);
  Logger.log("==================================================================");
}