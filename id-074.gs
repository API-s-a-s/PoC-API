/**
 * Estrategia para auditar la lista de IPs permitidas en el filtro de spam de Gmail.
 * Evalúa cuántas direcciones IP están configuradas para evadir los controles antispam.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-074.
 */
class GmailSpamFilterIpAllowlistStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-074
    const configIDs = [
      { 
        id: "ID-074", 
        valueKey: "valorPrincipal", // Retornará el número entero de IPs en la lista blanca
        noteKey: "comentario074",
        riskKey: "riesgo074",
        scoreKey: "score074"
      }
    ];

    super("Gmail Spam Filter IP Allowlist Audit", configIDs);
    
    // Aplicamos el filtro exacto de la API para 'gmail.email_spam_filter_ip_allowlist'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.email_spam_filter_ip_allowlist"`;
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
      Logger.log(`[ERROR] Spam Filter IP Allowlist Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo074: "Medio",
        score074: 2,
        comentario074: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide extraer y auditar la lista de direcciones IP exentas del filtro de spam."
      };
    }

    let allowedIpCount = 0;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const allowlistNode = setting.gmailEmailSpamFilterIpAllowlist || setting.emailSpamFilterIpAllowlist || setting;
      
      // Buscamos el arreglo de IPs
      const ips = allowlistNode.allowedIps || allowlistNode.ipAddresses || allowlistNode.ips || [];
      allowedIpCount = ips.length;
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo074, comentario074;

    if (allowedIpCount === 0) {
      // Caso 1: No hay IPs en la lista blanca (Seguro)
      riesgo074 = "Bajo";
      comentario074 = "La lista de direcciones IP permitidas (Allowlist) para evadir el filtro de spam se encuentra vacía. Todo el tráfico de correo entrante, sin importar su origen, está sujeto a la inspección estricta y a los motores de detección de amenazas de Google.";
    } else {
      // Caso 2: Existen IPs que evaden el spam (Riesgo Medio - Requiere revisión)
      riesgo074 = "Medio";
      comentario074 = "Indica la cantidad de direcciones IP externas que están configuradas explícitamente para evadir los controles antispam de Gmail. Esto requiere auditoría periódica, ya que los correos provenientes de estas IPs se entregarán directamente en las bandejas de entrada ignorando las heurísticas de seguridad.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Spam Filter IP Allowlist: Se detectaron ${allowedIpCount} IPs en la lista blanca. | Riesgo: ${riesgo074}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: allowedIpCount,
      comentario074: comentario074,
      riesgo074: riesgo074,
      score074: this.calcularScoreDeRiesgo(riesgo074)
    };
  }
}