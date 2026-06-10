/**
 * Estrategia para auditar el Análisis mejorado de mensajes previos a la entrega en Gmail.
 * Evalúa si el sistema retiene correos sospechosos para un escaneo profundo antes de entregarlos.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-075.
 */
class GmailEnhancedPreDeliveryScanningStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-075
    const configIDs = [
      { 
        id: "ID-075", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario075",
        riskKey: "riesgo075",
        scoreKey: "score075"
      }
    ];

    super("Gmail Enhanced Pre-Delivery Scanning Audit", configIDs);
    
    // Aplicamos el filtro exacto para 'gmail.enhanced_pre_delivery_message_scanning'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.enhanced_pre_delivery_message_scanning"`;
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
      Logger.log(`[ERROR] Enhanced Pre-Delivery Scanning Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo075: "Medio",
        score075: 2,
        comentario075: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si el escaneo profundo previo a la entrega está habilitado."
      };
    }

    let isEnhancedScanningEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const scanningNode = setting.gmailEnhancedPreDeliveryMessageScanning || setting.enhancedPreDeliveryMessageScanning || setting;
      
      // Verificamos el booleano específico de detección mejorada
      if (scanningNode.enableImprovedSuspiciousContentDetection === true || 
          scanningNode.enable_improved_suspicious_content_detection === true || 
          (scanningNode.state && scanningNode.state.toUpperCase() === 'ENABLED')) {
        isEnhancedScanningEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo075, comentario075;

    if (isEnhancedScanningEnabled) {
      // Caso 1: Escaneo mejorado habilitado (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo075 = "Bajo";
      comentario075 = "El análisis mejorado de mensajes previos a la entrega se encuentra habilitado. Esta configuración permite a Google retener temporalmente los correos sospechosos para someterlos a un escaneo heurístico profundo, bloqueando de manera efectiva amenazas de día cero y campañas de phishing avanzadas antes de que lleguen a la bandeja de entrada.";
    } else {
      // Caso 2: Escaneo mejorado deshabilitado (Riesgo Alto por phishing de día cero)
      respuestaConcreta = "Deshabilitado";
      riesgo075 = "Alto";
      comentario075 = "El análisis profundo previo a la entrega está deshabilitado. Los correos electrónicos sospechosos se entregan de inmediato a los usuarios sin pasar por el escaneo de seguridad adicional de Google, lo que incrementa significativamente el riesgo de que los empleados interactúen con ataques de phishing, enlaces maliciosos o malware de día cero.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Enhanced Pre-Delivery Scanning Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo075}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario075: comentario075,
      riesgo075: riesgo075,
      score075: this.calcularScoreDeRiesgo(riesgo075)
    };
  }
}
