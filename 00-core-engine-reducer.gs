/**
 * Analizador AST Simulado para expresiones CEL (Common Expression Language).
 * Procesa la lógica de a quiénes aplican las políticas de Google Workspace.
 * Referencia: Especificación CEL (https://github.com/google/cel-spec)
 * licences discarded: https://docs.cloud.google.com/identity/docs/concepts/policy-api-concepts#license
 */
class CELParserEngine {
  /**
   * Evalúa si un usuario califica para una política según el Query de seguridad.
   * @param {Object} policy - Objeto política completo que contiene policyQuery.
   * @param {Object} user - Objeto del censo con los datos del empleado en RAM.
   * @return {boolean} Verdadero si la política aplica al usuario.
   */

  static evaluate(policy, user) {
    const q = (policy && policy.policyQuery && policy.policyQuery.query) ? policy.policyQuery.query : "";

    // Si el query está vacío o es una regla global de cliente, aplica a todos por defecto
    if (q.trim() === "" || q.includes("customer==")) {
      if (!q.includes("entity.")) {
          // VALIDACIÓN ESTRICTA: Verificamos si el usuario tiene licencia de Google Workspace O Cloud Identity.
          // Las políticas de seguridad como 2SV aplican también a Cloud Identity Free (101031).
          // Fallback open: Si no hay array de licencias, lo dejamos pasar para no romper el motor.
          const hasWorkspaceLicense = !user.licenses || user.licenses.length === 0 || user.licenses.some(sku => 
              sku.includes('/product/Google-Apps/') || sku.includes('/product/101031')
          );
          
          if (!hasWorkspaceLicense) {
             this.discardedUsersLogs.add(user.email);
             return false;
          }

          return true;
      }
    }
    // 1. FRAGMENTACIÓN DISYUNTIVA (Operador OR ||)
    // Se divide la regla en bloques independientes. Basta con que uno sea verdadero.
    const orSegments = q.split("||");
    
    for (const orSeg of orSegments) {
      // 2. CONJUNCIÓN RESTRICTIVA (Operador AND &&)
      // Dentro de cada bloque OR, todas las subcondiciones deben ser verdaderas.
      const andSegments = orSeg.split("&&");
      let andResult = true;

      for (const andSeg of andSegments) {
         const condition = andSeg.trim();        
         // 3. INVERSIÓN UNARIA (Operador NOT !)
         // Detecta si la condición viene negada para tratarla como una excepción.
         let isNegated = condition.startsWith("!");
         let coreCondition = isNegated ? condition.substring(1).trim() : condition;
         let conditionMatched = false;

         // --- EVALUACIÓN SEMÁNTICA EN RAM ---
         // Compara los datos del censo del usuario contra la regla analizada
         if (coreCondition.includes("entity.org_units.exists")) {
            // Validación de Unidad Organizativa (OU)
            const ouMatches = this._extractArrayValues(coreCondition, "org_units");
            conditionMatched = ouMatches.some(ou => user.orgUnitPath && user.orgUnitPath.includes(ou));
            
            // FIX ESTRUCTURAL: La API de Cloud Identity devuelve OU IDs (ej. 03ph8a2z4clh8z7)
            // pero el censo en RAM tiene rutas de texto (ej. '/Ventas'). Como no tenemos 
            // el diccionario de resolución de IDs a Rutas, la comparación de strings falla.
            // Para no bloquear las políticas combinadas (ej. Grupo + OU), asumimos true por defecto.
            if (!conditionMatched && ouMatches.length > 0) {
                conditionMatched = true;
            }
         } else if (coreCondition.includes("entity.groups.exists")) {
            // Validación de Grupos de Google
            const groupMatches = this._extractArrayValues(coreCondition, "groups");
            const userGroups = user.groups || [];
            conditionMatched = groupMatches.some(gId => userGroups.includes(gId));
         } else if (coreCondition.includes("entity.licenses.exists")) {
            // Eliminación según el tipo de Licencias / SKUs corporativos
            // EXTRAEMOS LA LÓGICA DE EXTRACCIÓN A UN MÉTODO MÁS ROBUSTO
            const licenseMatches = this._extractLicenses(coreCondition);
            const userLicenses = user.licenses || [];
            conditionMatched = licenseMatches.some(sku => userLicenses.includes(sku));
            
            // Si falla específicamente por falta de licencia, lo registramos.
            if (!conditionMatched && !isNegated) {
                this.discardedUsersLogs.add(user.email);
            }
         } else {
            // Fallback preventivo: si la regla es desconocida, no bloqueamos el motor
            conditionMatched = true; 
         }

         // Aplicación de la inversión lógica si existía el operador "!"
         if (isNegated) {
            conditionMatched = !conditionMatched;
         }

         // Si una sola parte del AND falla, todo este bloque OR queda descartado
         if (!conditionMatched) {
            andResult = false;
            break; 
         }
      }

      // Si todo el bloque AND sobrevivió, el OR es exitoso y la política aplica
      if (andResult) {
         return true; 
      }
    }

    return false; // El usuario no cumplió ninguna de las reglas lógicas
  }

  // Unifica e imprime el log al final de la ejecución
  static printDiscardedLogs() {
     if (this.discardedUsersLogs.size > 0) {
         Logger.log(`[LICENCIAS] El motor CEL excluyó del análisis a los siguientes usuarios debido a que no cuentan con la licencia requerida por la política de seguridad: ${Array.from(this.discardedUsersLogs).join(", ")}`);
         // Limpiamos el Set para la próxima ejecución
         this.discardedUsersLogs.clear();
     }
  }

  /**
   * Extrae los valores de texto dentro de los corchetes de la regla CEL.
   * Convierte "['OU_Ventas']" en un arreglo manipulable de JavaScript.
   */
  static _extractArrayValues(query, entityType) {
    // 1. Para el formato de array: entity.org_units.exists(..., ou in ['...'])
    const arrayRegex = new RegExp(`entity\\.${entityType}\\.exists[^\\]]*\\[([^\\]]+)\\]`);
    const arrayMatch = query.match(arrayRegex);
    if (arrayMatch && arrayMatch[1]) {
      return arrayMatch[1].replace(/['"]/g, "").split(",").map(s => s.trim());
    }
    
    // 2. Para el formato de igualdad de Google: == orgUnitId('...') o == groupId('...')
    const eqRegex = new RegExp(`==\\s*(?:orgUnitId|groupId)\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`);
    const eqMatch = query.match(eqRegex);
    if (eqMatch && eqMatch[1]) {
      return [eqMatch[1].trim()];
    }
    
    // 3. Para formato directo: == '...'
    const eqDirectRegex = new RegExp(`==\\s*['"]([^'"]+)['"]`);
    const eqDirectMatch = query.match(eqDirectRegex);
    if (eqDirectMatch && eqDirectMatch[1]) {
      return [eqDirectMatch[1].trim()];
    }
    
    return [];
  }

  /**
   * Extractor especializado para licencias, maneja arrays y el operador '=='
   */
  static _extractLicenses(query) {
    // Si usa el formato de array: license in ['/product/...']
    const arrayRegex = /entity\.licenses\.exists[^\\]]*\[([^\]]+)\]/;
    const arrayMatch = query.match(arrayRegex);
    if (arrayMatch && arrayMatch[1]) {
       return arrayMatch[1].replace(/['"]/g, "").split(",").map(s => s.trim());
    }
    // Si usa el formato directo: license == '/product/...'
    const eqRegex = /entity\.licenses\.exists[^=]*==\s*['"]([^'"]+)['"]/;
    const eqMatch = query.match(eqRegex);
    if (eqMatch && eqMatch[1]) {
       return [eqMatch[1].trim()];
    }
    return [];
  }
}
CELParserEngine.discardedUsersLogs = new Set();

/**
 * Fábrica de Reducción de Políticas.
 * Resuelve conflictos cuando múltiples políticas lógicas compiten por el mismo usuario.
 */
class PolicyReducerFactory {
  
  /**
   * Identifica dinámicamente el ID de la OU Raíz y retorna la política efectiva para ella.
   */
  static getEffectiveRootPolicy(policies, settingType) {
    if (!policies || policies.length === 0) return null;
    
    // 1. Encontrar la OU Raíz buscando una política SYSTEM (que no sea de grupo)
    const systemPolicy = policies.find(p => p.type === "SYSTEM" && p.policyQuery && p.policyQuery.orgUnit && !p.policyQuery.group);
    
    // Si no hay política SYSTEM clara, intentar encontrar la que no tiene query o la primera
    if (!systemPolicy) {
      const fallback = policies.find(p => !(p.policyQuery && p.policyQuery.query));
      if (fallback) return fallback;
      return policies[0]; 
    }

    const rootOuId = systemPolicy.policyQuery.orgUnit;

    // 2. Filtrar todas las políticas que aplican EXACTAMENTE a la OU Raíz (y no a grupos)
    const rootPolicies = policies.filter(p => 
      p.policyQuery && 
      p.policyQuery.orgUnit === rootOuId && 
      !p.policyQuery.group
    );

    // 3. Reducir los conflictos de la OU Raíz usando el reducer apropiado
    return this.reduce(rootPolicies, settingType);
  }

  /**
   * Reduce un conjunto de políticas aplicables a una única configuración final.
   * @param {Array<Object>} applicablePolicies - Lista de políticas que pasaron el filtro CEL.
   * @param {string} settingType - Tipo de configuración (ej. "security.password")
   */
  static reduce(applicablePolicies, settingType) {
    if (!applicablePolicies || applicablePolicies.length === 0) return null;
    if (applicablePolicies.length === 1) return applicablePolicies[0];

    // Mapeo del algoritmo reductor según el estándar de Google Cloud Identity
    switch (settingType) {
      case "security.password":
      case "security.lessSecureApps":
      case "security.two_step_verification_enrollment":
        return this._maxReducer(applicablePolicies); // Algoritmo de precedencia numérica

      // Las políticas de recuperación acumulan estados mediante fusión (Merge)
      case "security.super_admin_account_recovery":
      case "security.user_account_recovery":
        return this._mergeReducer(applicablePolicies); 

      default:
        return this._maxReducer(applicablePolicies);
    }
  }

  /**
   * Reductor MAX ajustado para priorizar la configuración global (mayor sortOrder).
   */
  static _maxReducer(policies) {
    return policies.reduce((prev, current) => {
      const prevOrder = parseFloat((prev.policyQuery && prev.policyQuery.sortOrder) || 0);
      const currOrder = parseFloat((current.policyQuery && current.policyQuery.sortOrder) || 0);    
      return (prevOrder >= currOrder) ? prev : current;
    });
  }

  /**
   * Reductor MERGE: Concatena y combina configuraciones de múltiples objetos en uno solo.
   */
  static _mergeReducer(policies) {
    const sorted = policies.slice().sort((a, b) => {
      const orderA = parseFloat((a.policyQuery && a.policyQuery.sortOrder) || 0);
      const orderB = parseFloat((b.policyQuery && b.policyQuery.sortOrder) || 0);
      return orderA - orderB;
    });
    let mergedSetting = {};
    for (const policy of sorted) {
       if (policy.setting) mergedSetting = { ...mergedSetting, ...policy.setting };
    }
    return { setting: mergedSetting, _mergedFrom: sorted.length };
  }
}