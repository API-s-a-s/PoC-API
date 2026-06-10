/**
 * Estrategia para auditar la configuración del acceso IMAP en Gmail.
 * Evalúa si los usuarios tienen permitido sincronizar correos mediante protocolos heredados.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-063.
 */
class GmailImapAccessStrategy extends ApiStrategy {
  /**
   * Constructor de la estrategia.
   * @param {string} customerId - ID único del cliente en Google Workspace.
   */
  constructor(customerId) {
    // 1. Matriz de configuración requerida por la arquitectura base para vincular con Google Sheets
    const configIDs = [
      { 
        id: "ID-063", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario063",
        riskKey: "riesgo063",
        scoreKey: "score063"
      }
    ];

    super("Gmail IMAP Access Audit", configIDs);
    
    // Aplicamos el filtro exacto provisto por la API para el tipo de configuración 'gmail.imap_access'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.imap_access"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Email y DNS";
  }

  /**
   * Define la configuración de red y autenticación requerida para UrlFetchApp.
   */
  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  /**
   * Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico (Score).
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  /**
   * Procesa la respuesta JSON cruda de la API de Google y aplica reglas de negocio inyectadas.
   */
  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] Gmail IMAP Access Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo063: "Medio",
        score063: 2,
        comentario063: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si el acceso IMAP de Gmail está habilitado o restringido."
      };
    }

    let isImapAccessEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Manejamos las variaciones de anidación JSON típicas de las respuestas Cloud Identity
      const imapNode = setting.gmailImapAccess || setting.imapAccess || setting;
      
      // Verificamos si el estado explícito viene activado
      if (imapNode.enableImapAccess === true || imapNode.enable_imap_access === true || 
          (imapNode.state && imapNode.state.toUpperCase() === 'ENABLED')) {
        isImapAccessEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo063, comentario063;

    if (isImapAccessEnabled) {
      // Caso 1: IMAP está habilitado (Permisivo / Riesgo Alto)
      respuestaConcreta = "Habilitado";
      riesgo063 = "Alto";
      comentario063 = "El acceso por protocolo IMAP se encuentra habilitado en el dominio. Esto permite a los usuarios sincronizar y extraer correos electrónicos hacia clientes locales no autorizados o aplicaciones de terceros que evaden las directivas avanzadas de acceso condicional y el aprovisionamiento moderno basado en OAuth.";
    } else {
      // Caso 2: IMAP está deshabilitado (Restrictivo / Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo063 = "Bajo";
      comentario063 = "El acceso IMAP está deshabilitado de forma estricta en el tenant. Se bloquea el uso de credenciales en aplicaciones nativas o clientes de correo tradicionales no controlados, forzando el uso seguro de canales autorizados mediante mecanismos modernos de autenticación.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Gmail IMAP Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo063}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario063: comentario063,
      riesgo063: riesgo063,
      score063: this.calcularScoreDeRiesgo(riesgo063)
    };
  }
}