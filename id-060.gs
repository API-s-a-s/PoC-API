/**
 * Estrategia para auditar la configuración del Modo Confidencial de Gmail.
 * Evalúa si los usuarios pueden enviar correos con restricciones de reenvío/descarga.
 */
class GmailConfidentialModeStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-060", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario060",
        riskKey: "riesgo060",
        scoreKey: "score060"
      }
    ];

    super("Gmail Confidential Mode Audit", configIDs);
    this.category = "Email y DNS";
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

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const gmailPolicies = policies.filter(p => p.setting && p.setting.type === "gmail.confidential_mode");

    let isConfidentialModeEnabled = false;

    if (gmailPolicies.length === 0) {
      // Default in Workspace is disabled
      isConfidentialModeEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.confidential_mode");
      if (rootPolicy && rootPolicy.setting) {
        const confNode = rootPolicy.setting.gmailConfidentialMode || rootPolicy.setting.confidentialMode || rootPolicy.setting;
        if (confNode.enableConfidentialMode === true || confNode.enable_confidential_mode === true) {
          isConfidentialModeEnabled = true;
        }
      }
    }

    let respuestaConcreta;
    let riesgo060, comentario060;

    if (isConfidentialModeEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo060 = "Bajo";
      comentario060 = "El Modo Confidencial de Gmail se encuentra activo en el dominio, dotando a los usuarios de la capacidad de aplicar restricciones de reenvío, impedir descargas y configurar fechas de caducidad en sus correos, lo que mitiga sustancialmente la fuga de información sensible.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo060 = "Medio";
      comentario060 = "El Modo Confidencial de Gmail se encuentra inactivo. Los usuarios no pueden aplicar controles de expiración o restricciones de descarga a los correos electrónicos que envían, lo que incrementa el riesgo de exposición, copia o reenvío no autorizado de datos corporativos.";
    }

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario060: comentario060,
      riesgo060: riesgo060,
      score060: this.calcularScoreDeRiesgo(riesgo060)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo060: "", score060: "", comentario060: msg };
  }
}