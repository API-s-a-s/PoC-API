/**
 * Estrategia para auditar el uso de pasarelas de salida SMTP externas por usuario.
 * Evalúa si los usuarios pueden enviar correos a través de servidores SMTP de terceros.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-067.
 */
class GmailPerUserOutboundGatewayStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-067
    const configIDs = [
      { 
        id: "ID-067", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario067",
        riskKey: "riesgo067",
        scoreKey: "score067"
      }
    ];

    super("Gmail Per-User Outbound Gateway Audit", configIDs);
    
    // Aplicamos el filtro exacto para 'gmail.per_user_outbound_gateway'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.per_user_outbound_gateway"`;
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
      Logger.log(`[ERROR] Per-User Outbound Gateway Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo067: "Medio",
        score067: 2,
        comentario067: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si el uso de pasarelas SMTP externas está habilitado."
      };
    }

    let isOutboundGatewayEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const gatewayNode = setting.gmailPerUserOutboundGateway || setting.perUserOutboundGateway || setting;
      
      // Verificamos si el envío por SMTP externo está activo explícitamente
      if (gatewayNode.enablePerUserOutboundGateway === true || 
          gatewayNode.enable_per_user_outbound_gateway === true || 
          (gatewayNode.state && gatewayNode.state.toUpperCase() === 'ENABLED')) {
        isOutboundGatewayEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo067, comentario067;

    if (isOutboundGatewayEnabled) {
      // Caso 1: Pasarela SMTP externa habilitada (Riesgo Alto por evasión de DLP/Vault)
      respuestaConcreta = "Habilitado";
      riesgo067 = "Alto";
      comentario067 = "La configuración permite a los usuarios utilizar pasarelas de salida (SMTP) externas. Esto representa un alto riesgo de cumplimiento y seguridad, ya que los correos enviados a través de servidores de terceros evaden los controles de Prevención de Pérdida de Datos (DLP) del dominio, escapan de las políticas de enrutamiento y no quedan registrados en el archivo legal de Google Vault.";
    } else {
      // Caso 2: Pasarela SMTP externa deshabilitada (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo067 = "Bajo";
      comentario067 = "El uso de pasarelas de salida (SMTP) externas por usuario se encuentra restringido de manera estricta. Todo el tráfico de correo saliente está obligado a transitar a través de la infraestructura autorizada de Google Workspace, garantizando la retención en Vault y la aplicación de políticas DLP.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Per-User Outbound Gateway Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo067}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario067: comentario067,
      riesgo067: riesgo067,
      score067: this.calcularScoreDeRiesgo(riesgo067)
    };
  }
}