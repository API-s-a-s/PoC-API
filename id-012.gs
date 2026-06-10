/**
 * Estrategia de Métodos Permitidos para la Verificación en 2 pasos (MFA Factors).
 * Propósito: Auditar la calidad del 2SV, detectando vulnerables a intercepción (como SMS o llamadas de voz).
 * Referencia: security.two_step_verification_enforcement_factor
 */
class Allowed2SVMethodsPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-012", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario012",
        riskKey: "riesgo012",
        scoreKey: "score012"
      }
    ];

    super("Allowed 2SV Methods Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE FACTORES DE MFA
    // =======================================================================
    const factorPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_enforcement_factor"));
    Logger.log(`[ID-012] Políticas de Factores MFA encontradas en memoria: ${factorPolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API
    // Si la API no retorna nada, Google por defecto permite TODOS los métodos (ALL).
    // =======================================================================
    if (factorPolicies.length === 0) {
      Logger.log("[DEBUG ID-012] ALERTA: La API no retorna datos para métodos de 2SV.");
      return {
        name: this.name,
        valorPrincipal: "empty.",
        comentario012: "omitió datos.",
        riesgo012: "",
        score012: ""
      };
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // Buscamos la regla general y traducimos el valor de la API a lenguaje humano.
    // =======================================================================
    const rootPolicy = factorPolicies.find(p => !(p.query || "").includes("entity."));
    
    // Extraemos el factor permitido (Por defecto es ALL si no está definido)
    const rootFactor = this._extractFactor(rootPolicy);
    
    // Interpretación del valor para la celda de salida (valorPrincipal)
    let estadoPrincipal = "";
    let riesgoRaiz = "Alto"; // Por defecto asumimos riesgo alto si se permiten SMS

    switch (rootFactor) {
      case "ALL":
      case "ANY":
        estadoPrincipal = "Cualquiera (Incluye SMS)";
        riesgoRaiz = "Alto"; // Permite SMS, alto riesgo de SIM Swapping
        break;
      case "NO_TELEPHONY":
        estadoPrincipal = "Sin telefonía (Seguro)";
        riesgoRaiz = "Bajo";
        break;
      case "PASSKEY_ONLY":
        estadoPrincipal = "Solo Passkeys (Muy Seguro)";
        riesgoRaiz = "Bajo";
        break;
      case "PASSKEY_PLUS_SECURITY_CODE":
        estadoPrincipal = "Passkeys + Código";
        riesgoRaiz = "Bajo";
        break;
      case "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE":
        estadoPrincipal = "Passkeys + Código (IP Ligada)";
        riesgoRaiz = "Bajo";
        break;
      default:
        estadoPrincipal = rootFactor; // Fallback por si Google añade nuevos métodos
        riesgoRaiz = "Medio";
    }

    Logger.log(`[ID-012] Raíz de la Org: Método MFA permitido = ${rootFactor} (${estadoPrincipal})`);

    // =======================================================================
    // PASO 4: CALCULAR COBERTURA DE USUARIOS (CENSO)
    // Dividimos a los usuarios entre los que tienen políticas "Fuertes" y "Débiles".
    // =======================================================================
    let usuariosConMetodosDebiles = 0; // Usan ALL o ANY
    let usuariosConMetodosFuertes = 0; // Usan NO_TELEPHONY o PASSKEYS
    
    for (const user of census) {
      const aplicables = factorPolicies.filter(p => CELParserEngine.evaluate(p, user));
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_enforcement_factor");

      const userFactor = this._extractFactor(politicaGanadora);

      if (userFactor === "ALL" || userFactor === "ANY") {
        usuariosConMetodosDebiles++;
      } else {
        usuariosConMetodosFuertes++;
      }
    }

    const totalUsuarios = usuariosConMetodosFuertes + usuariosConMetodosDebiles;
    
    // Calculamos el % de usuarios PROTEGIDOS (que NO pueden usar SMS)
    const porcentajeProtegidos = totalUsuarios > 0 ? Math.round((usuariosConMetodosFuertes / totalUsuarios) * 100) : 0;
    
    // =======================================================================
    // PASO 5: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // =======================================================================
    let comentario = `${porcentajeProtegidos}%`; // Imprimimos el porcentaje de usuarios protegidos (con métodos fuertes)
    
    Logger.log(`[ID-012] Métrica procesada. Riesgo Raíz: ${riesgoRaiz}. Usuarios con métodos seguros: ${porcentajeProtegidos}%`);

    return {
      name: this.name,
      valorPrincipal: estadoPrincipal, 
      comentario012: comentario,
      riesgo012: riesgoRaiz,
      score012: this.calcularScoreDeRiesgo(riesgoRaiz)
    };
  }

  // =======================================================================
  // HELPER: Extrae el valor exacto del método permitido soportando variantes
  // =======================================================================
  _extractFactor(policy) {
    if (!policy || !policy.setting) return "ALL"; 
    
    const configNode = policy.setting.value || policy.setting;
    const factorNode = configNode.twoStepVerificationEnforcementFactor || configNode;
    
    // Buscamos las variables mapeadas en la documentación de Google
    const factor = factorNode.allowed_sign_in_factor_set || factorNode.allowedSignInFactorSet;
    
    return factor ? factor.toUpperCase() : "ALL";
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
    Logger.log(`[ID-012] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo012: "",
      score012: "",
      comentario012: msg
    };
  }
}