/**
 * Estrategia para auditar la seguridad (escaneo) de enlaces e imágenes externas en Gmail.
 * Evalúa si el sistema escanea activamente URLs acortadas o incrustadas en busca de amenazas.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-071.
 */
class GmailLinksExternalImagesSecurityStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-071
    const configIDs = [
      { 
        id: "ID-071", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario071",
        riskKey: "riesgo071",
        scoreKey: "score071"
      }
    ];

    super("Gmail Links and External Images Security Audit", configIDs);
    
    // Aplicamos el filtro exacto para 'gmail.links_and_external_images'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.links_and_external_images"`;
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
      Logger.log(`[ERROR] Links & External Images Security Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo071: "Medio",
        score071: 2,
        comentario071: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente si el escaneo de seguridad en URLs e imágenes está habilitado."
      };
    }

    let isScanningEnabled = false;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const securityNode = setting.gmailLinksAndExternalImages || setting.linksAndExternalImages || setting;
      
      // Verificamos explícitamente el parámetro de escaneo de imágenes/enlaces externos
      if (securityNode.enableExternalImageScanning === true || 
          securityNode.enable_external_image_scanning === true || 
          (securityNode.state && securityNode.state.toUpperCase() === 'ENABLED')) {
        isScanningEnabled = true;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo071, comentario071;

    if (isScanningEnabled) {
      // Caso 1: Escaneo de seguridad habilitado (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo071 = "Bajo";
      comentario071 = "El escaneo de seguridad para enlaces e imágenes externas se encuentra habilitado. El entorno de Google Workspace inspecciona activamente las URLs incrustadas y los enlaces acortados para identificar y bloquear amenazas antes de que el usuario interactúe con ellos, mitigando riesgos de phishing y malware.";
    } else {
      // Caso 2: Escaneo de seguridad deshabilitado (Riesgo Alto por phishing)
      respuestaConcreta = "Deshabilitado";
      riesgo071 = "Alto";
      comentario071 = "El escaneo de seguridad en enlaces e imágenes se encuentra deshabilitado. Esta configuración expone a los usuarios a riesgos críticos, ya que permite que URLs maliciosas o acortadores engañosos lleguen a la bandeja de entrada sin ser evaluados por los motores de Safe Browsing, facilitando ataques de suplantación de identidad.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Links & External Images Security Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo071}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario071: comentario071,
      riesgo071: riesgo071,
      score071: this.calcularScoreDeRiesgo(riesgo071)
    };
  }
}