/**
 * Estrategia para auditar la configuración de reenvío automático (Auto-Forwarding) de Gmail.
 * Evalúa si los usuarios tienen permitido configurar reglas para reenviar correos a cuentas externas.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-065.
 */
class GmailAutoForwardingStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-065
    const configIDs = [
      { 
        id: "ID-065", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario065",
        riskKey: "riesgo065",
        scoreKey: "score065"
      }
    ];

    super("Gmail Auto-Forwarding Audit", configIDs);
    
    // Aplicamos el filtro exacto para 'gmail.auto_forwarding'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.auto_forwarding"`;
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
      Logger.log(`[ERROR] Gmail Auto-Forwarding Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo065: "Medio",
        score065: 2,
        comentario065: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si el reenvío automático de correos está habilitado en el dominio."
      };
    }

    let isAutoForwardingEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const forwardingNode = setting.gmailAutoForwarding || setting.autoForwarding || setting;
      
      // Verificamos si el reenvío automático está activo explícitamente
      if (forwardingNode.enableAutoForwarding === true || 
          forwardingNode.enable_auto_forwarding === true || 
          (forwardingNode.state && forwardingNode.state.toUpperCase() === 'ENABLED')) {
        isAutoForwardingEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo065, comentario065;

    if (isAutoForwardingEnabled) {
      // Caso 1: Reenvío automático habilitado (Riesgo Alto por exfiltración)
      respuestaConcreta = "Habilitado";
      riesgo065 = "Alto";
      comentario065 = "El reenvío automático de correos (Auto-Forwarding) se encuentra habilitado en el dominio. Esto representa una vulnerabilidad crítica de exfiltración de datos, ya que permite a usuarios (o atacantes en cuentas comprometidas) configurar reglas para desviar silenciosamente copias de correos corporativos hacia direcciones personales o externas.";
    } else {
      // Caso 2: Reenvío automático deshabilitado (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo065 = "Bajo";
      comentario065 = "El reenvío automático de correos se encuentra restringido. Se impide que los usuarios configuren reglas de enrutamiento que envíen automáticamente los mensajes entrantes hacia cuentas externas, garantizando que el flujo de información permanezca dentro del perímetro seguro de la organización.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Gmail Auto-Forwarding Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo065}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario065: comentario065,
      riesgo065: riesgo065,
      score065: this.calcularScoreDeRiesgo(riesgo065)
    };
  }
}