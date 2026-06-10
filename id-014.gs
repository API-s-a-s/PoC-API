/**
 * Estrategia para auditar los Códigos de Seguridad (SignIn Codes / Backup Codes).
 * Propósito: Detectar si los usuarios pueden generar códigos en g.co/sc que 
 * permitan a un atacante remoto saltarse la verificación en dos pasos o Passkeys.
 * Referencia: security.two_step_verification_sign_in_code
 */
class TwoStepVerificationSignInCodePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-014", 
        valueKey: "valorPrincipal",
        noteKey: "comentario014",
        riskKey: "riesgo014",
        scoreKey: "score014"
      }
    ];

    super("2SV SignIn Codes Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE CÓDIGOS DE SEGURIDAD
    // =======================================================================
    const signInCodePolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_sign_in_code"));
    Logger.log(`[ID-014] Políticas de Códigos de Seguridad encontradas: ${signInCodePolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API
    // Si la API no retorna nada, imprimimos empty.
    // =======================================================================
    if (signInCodePolicies.length === 0) {
      Logger.log("[DEBUG ID-014] ALERTA: La API no retorna datos para códigos de seguridad.");
      return {
        name: this.name,
        valorPrincipal: "empty.",
        comentario014: "omitió datos.",
        riesgo014: "",
        score014: ""
      };
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // =======================================================================
    const rootPolicy = signInCodePolicies.find(p => !(p.query || "").includes("entity."));
    const rootState = this._extractSignInCodeState(rootPolicy);
    
    let estadoPrincipal = "";
    let riesgoRaiz = "Alto"; 

    // Interpretación Forense del Enum
    switch (rootState) {
      case "ALLOWED_WITH_REMOTE_ACCESS":
        estadoPrincipal = "Permitido (Acceso Remoto)";
        riesgoRaiz = "Alto"; 
        break;
      case "ALLOWED_WITHOUT_REMOTE_ACCESS":
        estadoPrincipal = "Permitido (Solo entorno seguro)";
        riesgoRaiz = "Medio"; // Mitiga el phishing remoto, pero sigue permitiendo códigos
        break;
      case "NOT_ALLOWED":
        estadoPrincipal = "Bloqueado (Seguro)";
        riesgoRaiz = "Bajo"; // Cierra el vector de ataque g.co/sc
        break;
      default:
        estadoPrincipal = "Desconocido";
        riesgoRaiz = "Medio";
    }

    Logger.log(`[ID-014] Raíz de la Org: Estado de Códigos de Seguridad = ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: CALCULAR VULNERABILIDAD EN EL CENSO
    // Evaluamos cuántos usuarios tienen habilitado el acceso REMOTO (Riesgo Crítico)
    // =======================================================================
    let usuariosConAccesoRemoto = 0; // Vulnerables a phishing remoto (g.co/sc)
    let usuariosProtegidos = 0; // Bloqueados o sin acceso remoto
    
    for (const user of census) {
      const aplicables = signInCodePolicies.filter(p => CELParserEngine.evaluate(p, user));
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_sign_in_code");

      const userState = this._extractSignInCodeState(politicaGanadora);

      if (userState === "ALLOWED_WITH_REMOTE_ACCESS") {
        usuariosConAccesoRemoto++;
      } else {
        usuariosProtegidos++;
      }
    }

    const totalUsuarios = usuariosConAccesoRemoto + usuariosProtegidos;
    const porcentajeVulnerables = totalUsuarios > 0 ? Math.round((usuariosConAccesoRemoto / totalUsuarios) * 100) : 0;
    
    // =======================================================================
    // PASO 5: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // =======================================================================
    let comentario = "";
    
    if (porcentajeVulnerables > 0) {
      comentario = `El ${porcentajeVulnerables}% de los usuarios pueden generar códigos de seguridad con acceso remoto. Esto es un vector crítico de ingeniería social (phishing) que permite a atacantes saltarse la verificación en dos pasos.`;
    } else if (rootState === "ALLOWED_WITHOUT_REMOTE_ACCESS") {
      comentario = "La generación de códigos está permitida, pero restringida sin acceso remoto. Esto mitiga ataques externos, pero se recomienda NOT_ALLOWED para seguridad Zero Trust.";
    } else {
      comentario = "El 100% de la organización tiene bloqueada la generación de códigos de seguridad, cerrando efectivamente este vector de ataque.";
    }
    
    Logger.log(`[ID-014] Métrica procesada. Riesgo: ${riesgoRaiz}. Usuarios expuestos a acceso remoto: ${porcentajeVulnerables}%`);

    return {
      name: this.name,
      valorPrincipal: estadoPrincipal, 
      comentario014: comentario,
      riesgo014: riesgoRaiz,
      score014: this.calcularScoreDeRiesgo(riesgoRaiz)
    };
  }

  // =======================================================================
  // HELPER: Extracción Robusta del Enum
  // Escanea el JSON completo buscando las llaves de estado definidas por Google.
  // =======================================================================
  _extractSignInCodeState(policy) {
    if (!policy || !policy.setting) return "UNKNOWN";
    
    const configNode = policy.setting.value || policy.setting;
    const nodeStr = JSON.stringify(configNode);

    // Usamos una lectura resiliente de strings para evitar fallos si Google cambia 
    // el nombre de la llave que contiene el Enum en futuras versiones de la API.
    if (nodeStr.includes("ALLOWED_WITH_REMOTE_ACCESS")) {
      return "ALLOWED_WITH_REMOTE_ACCESS";
    } else if (nodeStr.includes("ALLOWED_WITHOUT_REMOTE_ACCESS")) {
      return "ALLOWED_WITHOUT_REMOTE_ACCESS";
    } else if (nodeStr.includes("NOT_ALLOWED")) {
      return "NOT_ALLOWED";
    }

    // Fallback por si la política utiliza booleanos antiguos en lugar del nuevo Enum
    if (configNode.allow_sign_in_code === true || configNode.allowSignInCode === true) {
      return "ALLOWED_WITH_REMOTE_ACCESS"; // Asumimos el peor escenario si estaba en true
    } else if (configNode.allow_sign_in_code === false || configNode.allowSignInCode === false) {
      return "NOT_ALLOWED";
    }

    return "UNKNOWN";
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Handler de errores en memoria
  _buildErrorResponse(msg) {
    Logger.log(`[ID-014] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo014: "",
      score014: "",
      comentario014: msg
    };
  }
}