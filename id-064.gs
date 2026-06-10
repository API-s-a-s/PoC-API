/**
 * Estrategia para auditar la configuración de Google Workspace Sync para Microsoft Outlook (GWSMO).
 * Evalúa si los usuarios pueden sincronizar datos de la cuenta en clientes de escritorio de Outlook.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-064.
 */
class WorkspaceSyncForOutlookStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-064
    const configIDs = [
      { 
        id: "ID-064", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario064",
        riskKey: "riesgo064",
        scoreKey: "score064"
      }
    ];

    super("Workspace Sync for Outlook Audit", configIDs);
    
    // Aplicamos el filtro exacto para 'gmail.workspace_sync_for_outlook'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.workspace_sync_for_outlook"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Email y DNS";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] Workspace Sync for Outlook Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo064: "Medio",
        score064: 2,
        comentario064: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si la sincronización para Microsoft Outlook está habilitada."
      };
    }

    let isSyncEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const syncNode = setting.gmailWorkspaceSyncForOutlook || setting.workspaceSyncForOutlook || setting;
      
      // Verificamos si la sincronización está activa explícitamente
      if (syncNode.enableWorkspaceSyncForOutlook === true || 
          syncNode.enable_workspace_sync_for_outlook === true || 
          (syncNode.state && syncNode.state.toUpperCase() === 'ENABLED')) {
        isSyncEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo064, comentario064;

    if (isSyncEnabled) {
      // Caso 1: GWSMO habilitado (Riesgo Alto por fuga a PST local)
      respuestaConcreta = "Habilitado";
      riesgo064 = "Alto";
      comentario064 = "Google Workspace Sync para Microsoft Outlook (GWSMO) se encuentra habilitado. Los usuarios pueden descargar y sincronizar correos, calendarios y contactos hacia un cliente local, creando archivos de almacenamiento (PST) en sus dispositivos que evaden los controles de DLP y seguridad nativos de la nube.";
    } else {
      // Caso 2: GWSMO deshabilitado (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo064 = "Bajo";
      comentario064 = "La sincronización de Google Workspace para Microsoft Outlook se encuentra deshabilitada de forma estricta. Se bloquea la extracción y el almacenamiento local de información corporativa hacia clientes de escritorio heredados.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Workspace Sync for Outlook Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo064}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario064: comentario064,
      riesgo064: riesgo064,
      score064: this.calcularScoreDeRiesgo(riesgo064)
    };
  }
}