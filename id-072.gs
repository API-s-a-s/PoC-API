/**
 * Estrategia para auditar las directivas avanzadas de protección contra spoofing y autenticación en Gmail.
 * Evalúa si el dominio cuenta con escudos activos frente a ataques BEC y suplantación de nombres/dominios.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-072.
 */
class GmailSpoofingAndAuthenticationStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para asociar los resultados con el ID-072 en Google Sheets
    const configIDs = [
      { 
        id: "ID-072", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario072",
        riskKey: "riesgo072",
        scoreKey: "score072"
      }
    ];

    super("Gmail Spoofing and Authentication Safety Audit", configIDs);
    
    // Aplicamos el filtro exacto de la API para 'gmail.spoofing_and_authentication'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.spoofing_and_authentication"`;
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

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico (Score)
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
      Logger.log(`[ERROR] Spoofing and Authentication Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo072: "Medio",
        score072: 2,
        comentario072: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide evaluar técnicamente las políticas avanzadas de protección contra spoofing y autenticación en Gmail."
      };
    }

    let isSpoofingProtectionEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones en el nombre del nodo debido al estado beta de la API
      const spoofNode = setting.gmailSpoofingAndAuthentication || setting.spoofingAndAuthentication || setting;
      
      // Validamos si las reglas de protección avanzada están activas
      if (spoofNode.enableSpoofingAndAuthentication === true || 
          spoofNode.enable_spoofing_and_authentication === true || 
          (spoofNode.state && spoofNode.state.toUpperCase() === 'ENABLED')) {
        isSpoofingProtectionEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo072, comentario072;

    if (isSpoofingProtectionEnabled) {
      // Caso 1: Protección contra spoofing activa (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo072 = "Bajo";
      comentario072 = "Las protecciones avanzadas contra suplantación de identidad (spoofing) y validación de autenticación de correo están habilitadas. El sistema analiza activamente los mensajes entrantes para bloquear intentos de phishing dirigidos, suplantación de nombres de ejecutivos o dominios homógrafos, y flujos que fallen los controles rigurosos de SPF/DKIM.";
    } else {
      // Caso 2: Sin protección avanzada (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo072 = "Alto";
      comentario072 = "Las protecciones avanzadas contra spoofing y suplantadores de identidad en Gmail están deshabilitadas. La organización carece de defensas estrictas y algoritmos de IA para mitigar ataques de Business Email Compromise (BEC) y manipulación de cabeceras, incrementando severamente la exposición al engaño de los usuarios.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Spoofing & Auth Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo072}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario072: comentario072,
      riesgo072: riesgo072,
      score072: this.calcularScoreDeRiesgo(riesgo072)
    };
  }
}