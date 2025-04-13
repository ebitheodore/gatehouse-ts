/**
 * Operation types for combining policies.
 */
const CombineOp = Object.freeze({
  And: 'AND',
  Or: 'OR',
  Not: 'NOT',
});

type Operation = (typeof CombineOp)[keyof typeof CombineOp];

/**
 * Base class for policy evaluation results.
 * Contains information about whether access was granted and why.
 */
abstract class PolicyEvalResult {
  public readonly policyType: string;
  public readonly reason: string | null;
  constructor({ policyType, reason }: { policyType: string; reason?: string | null }) {
    this.policyType = policyType;
    this.reason = reason ?? null;
  }

  abstract isGranted(): boolean;
  abstract format(): string;
}

/**
 * Represents a successful policy evaluation that grants access.
 */
class GrantedAccessResult extends PolicyEvalResult {
  isGranted(): boolean {
    return true;
  }
  format(): string {
    return `✔ ${this.policyType} GRANTED${this.reason ? ' ' + this.reason : ''}`;
  }
}

/**
 * Represents a failed policy evaluation that denies access.
 */
class DeniedAccessResult extends PolicyEvalResult {
  isGranted(): boolean {
    return false;
  }
  format(): string {
    return `✘ ${this.policyType} DENIED: ${this.reason ? ' ' + this.reason : ''}`;
  }
}

/**
 * Represents a combined result from multiple policies.
 * Used for AND, OR, and NOT policy combinations.
 */
class CombinedResult extends PolicyEvalResult {
  private readonly outcome: boolean;
  private readonly operation: Operation;
  private readonly children: PolicyEvalResult[];

  constructor({
    policyType,
    outcome,
    operation,
    children,
  }: {
    policyType: string;
    outcome: boolean;
    operation: Operation;
    children: PolicyEvalResult[];
  }) {
    super({ policyType, reason: null });
    this.outcome = outcome;
    this.operation = operation;
    this.children = children;
  }
  isGranted(): boolean {
    return this.outcome;
  }
  format(): string {
    const outcomeChar: string = this.outcome ? '✔' : '✘';
    const toplevelMessage = `${outcomeChar} ${this.policyType} (${this.operation})`;
    return [toplevelMessage, ...this.children.map((child) => '  ' + child.format())].join(
      '\n'
    );
  }

  display() {
    console.log(this.format());
  }
}

/**
 * Contains the full evaluation trace for debugging policy decisions.
 */
class EvalTrace {
  private readonly root: PolicyEvalResult | null;

  constructor(root: PolicyEvalResult | null = null) {
    this.root = root;
  }

  format(): string {
    return this.root?.format() || 'No evaluation trace available';
  }
}

/**
 * Final result of an access evaluation.
 * Contains the outcome (granted/denied), reason, and full evaluation trace.
 *
 * @example
 * const result = await permissionChecker.evaluateAccess({
 *   subject: user,
 *   resource: document,
 *   action: "edit",
 *   context: {}
 * });
 *
 * if (result.isGranted()) {
 *   // Allow the action
 * } else {
 *   console.log("Access denied:", result.getDisplayTrace());
 * }
 */
class AccessEvaluation {
  private readonly outcome: 'Granted' | 'Denied';
  private readonly trace: EvalTrace;
  private readonly policyType: string | null;
  public readonly reason: string | null;
  private constructor({
    outcome,
    reason,
    policyType,
    trace,
  }:
    | {
        outcome: 'Granted';
        reason?: string | null;
        policyType: string;
        trace: EvalTrace;
      }
    | {
        outcome: 'Denied';
        reason: string;
        policyType?: null;
        trace: EvalTrace;
      }) {
    this.outcome = outcome;
    this.trace = trace;
    this.reason = reason || null;
    this.policyType = policyType || null;
  }

  static denied(reason: string, trace: EvalTrace): AccessEvaluation {
    return new AccessEvaluation({
      reason,
      policyType: null,
      trace,
      outcome: 'Denied',
    });
  }

  static granted(
    policyType: string,
    trace: EvalTrace,
    reason: string | null = null
  ): AccessEvaluation {
    return new AccessEvaluation({
      reason,
      policyType,
      trace,
      outcome: 'Granted',
    });
  }

  /**
   * Returns whether access was granted.
   *
   * @returns true if access was granted, false otherwise
   */
  isGranted(): boolean {
    return this.outcome === 'Granted';
  }

  /**
   * Returns a formatted string with the evaluation trace for debugging.
   *
   * @returns Formatted evaluation trace
   */
  getDisplayTrace(): string {
    const traceString = this.trace.format();
    return traceString !== 'No evaluation trace available'
      ? `\nEvaluation Trace:\n${traceString}`
      : `\n(${traceString})`;
  }

  /**
   * Prints the evaluation result to the console.
   */
  print() {
    if (this.outcome === 'Granted') {
      console.log(
        `[GRANTED] by ${this.policyType}${this.reason ? ` - ${this.reason}` : ''}`
      );
    } else {
      console.log(`[DENIED] - ${this.reason}`);
    }
  }
}

/**
 * Function type for evaluating access based on subject, resource, action, and context.
 *
 * @template Subject - The type of the subject requesting access
 * @template Resource - The type of resource being accessed
 * @template Action - The type of action being performed
 * @template Context - Additional contextual information
 */
type EvaluateAccess<Subject, Resource, Action, Context> = ({
  subject,
  resource,
  action,
  context,
}: {
  subject: Subject;
  resource: Resource;
  action: Action;
  context: Context;
}) => PolicyEvalResult | Promise<PolicyEvalResult>;

/**
 * Interface for all policy types in the system.
 *
 * @template Subject - The type of the subject requesting access
 * @template Resource - The type of resource being accessed
 * @template Action - The type of action being performed
 * @template Context - Additional contextual information
 */
interface Policy<Subject, Resource, Action, Context> {
  /**
   * @param subject The entity requesting access.
   * @param action The action being performed.
   * @param resource The target resource.
   * @param context Additional context that may affect the decision.
   */
  readonly evaluateAccess: EvaluateAccess<Subject, Resource, Action, Context>;

  /**
   * Policy name for debugging.
   */
  readonly name: string;
}

/**
 * Main class for evaluating access permissions. Add multiple policies to it,
 * and it will evaluate them sequentially until one grants access.
 *
 * @template Sub - The type of the subject requesting access
 * @template Res - The type of resource being accessed
 * @template Act - The type of action being performed
 * @template Ctx - Additional contextual information
 *
 * @example
 * const checker = new PermissionChecker<User, Document, string, RequestContext>();
 * checker.addPolicy(adminPolicy);
 * checker.addPolicy(ownerPolicy);
 * const result = await checker.evaluateAccess({
 *   subject: currentUser,
 *   resource: document,
 *   action: "edit",
 *   context: requestContext
 * });
 * if (result.isGranted()) {
 *   // Allow access
 * }
 */
class PermissionChecker<Sub, Res, Act, Ctx> {
  private policies: Policy<Sub, Res, Act, Ctx>[];
  public readonly name: string = 'PermissionChecker';
  constructor() {
    this.policies = [];
  }

  /**
   * Adds a policy to the permission checker.
   * Policies are evaluated in the order they're added, with OR semantics.
   *
   * @param policy The policy to add
   */
  addPolicy(policy: Policy<Sub, Res, Act, Ctx>) {
    this.policies.push(policy);
  }

  /**
   * Evaluates access based on the configured policies.
   * Policies are evaluated sequentially with OR semantics (short-circuiting on first success).
   *
   * @param subject The entity requesting access.
   * @param action The action being performed.
   * @param resource The target resource.
   * @param context Additional context that may affect the decision.
   * @returns AccessEvaluation result with details about the decision
   */
  async evaluateAccess({
    subject,
    resource,
    action,
    context,
  }: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }): Promise<AccessEvaluation> {
    if (!this.policies.length) {
      const reason: string = 'No policies configured';
      console.warn(reason);
      const result = new DeniedAccessResult({
        policyType: 'PermissionChecker',
        reason,
      });
      return AccessEvaluation.denied(reason, new EvalTrace(result));
    }

    const policyResults: PolicyEvalResult[] = [];
    for (const policy of this.policies) {
      const result: PolicyEvalResult = await policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      });
      const resultPassed: boolean = result.isGranted();
      policyResults.push(result);

      if (resultPassed) {
        const combined = new CombinedResult({
          policyType: 'PermissionChecker',
          outcome: true,
          operation: CombineOp.Or,
          children: policyResults,
        });
        return AccessEvaluation.granted(result.policyType, new EvalTrace(combined));
      }
    }

    const combined = new CombinedResult({
      policyType: 'PermissionChecker',
      outcome: false,
      operation: CombineOp.Or,
      children: policyResults,
    });
    return AccessEvaluation.denied('All policies denied access', new EvalTrace(combined));
  }
}

/**
 * Represents the intended effect of a policy.
 * `Allow` means the policy grants access; `Deny` means it denies access.
 */
const Effect = Object.freeze({
  Allow: 'Allow',
  Deny: 'Deny',
});

type IntendedEffect = (typeof Effect)[keyof typeof Effect];

type InternalPolicy<Sub, Res, Act, Ctx> = {
  name: string;

  effect: IntendedEffect;

  predicate: (
    subject: Sub,
    resource: Res,
    action: Act,
    context: Ctx
  ) => boolean | Promise<boolean>;
};

function transformInternalPolicy<Sub, Res, Act, Ctx>(
  internalPolicy: InternalPolicy<Sub, Res, Act, Ctx>
): Policy<Sub, Res, Act, Ctx> {
  const policyName: string = internalPolicy.name;
  const effect: IntendedEffect = internalPolicy.effect;
  return Object.freeze({
    name: policyName,
    evaluateAccess: async ({
      subject,
      resource,
      action,
      context,
    }: {
      subject: Sub;
      resource: Res;
      action: Act;
      context: Ctx;
    }): Promise<PolicyEvalResult> => {
      const predicateResult = await internalPolicy.predicate(
        subject,
        resource,
        action,
        context
      );
      if (predicateResult) {
        if (effect === Effect.Allow) {
          return new GrantedAccessResult({
            policyType: policyName,
            reason: 'Policy allowed access',
          });
        }

        return new DeniedAccessResult({
          policyType: policyName,
          reason: 'Policy denied access',
        });
      }

      return new DeniedAccessResult({
        policyType: policyName,
        reason: 'Policy predicate did not match',
      });
    },
  });
}

/**
 * Function type for checking if access conditions are met.
 * Used in ABAC policies and other conditional checks.
 *
 * @template Subject - The type of the subject requesting access
 * @template Resource - The type of resource being accessed
 * @template Action - The type of action being performed
 * @template Context - Additional contextual information
 */
type Condition<Subject, Resource, Action, Context> = ({
  subject,
  resource,
  action,
  context,
}: {
  subject: Subject;
  resource: Resource;
  action: Action;
  context: Context;
}) => boolean | Promise<boolean>;

/**
 * A fluent builder for creating custom access policies.
 *
 * @template Sub - The type of the subject requesting access
 * @template Res - The type of resource being accessed
 * @template Act - The type of action being performed
 * @template Ctx - Additional contextual information
 *
 * @example
 * const readOnlyPolicy = new PolicyBuilder<User, Document, string, Context>("ReadOnly")
 *   .actions(action => action === "read")
 *   .build();
 */
class PolicyBuilder<Sub, Res, Act, Ctx> {
  private name: string;
  private internalEffect: IntendedEffect;

  private subjectPred: ((sub: Sub) => boolean | Promise<boolean>) | null = null;
  private resPred: ((res: Res) => boolean | Promise<boolean>) | null = null;
  private actionPred: ((act: Act) => boolean | Promise<boolean>) | null = null;
  private ctxPred: ((ctx: Ctx) => boolean | Promise<boolean>) | null = null;
  private extraConditionPred: Condition<Sub, Res, Act, Ctx> | null = null;

  constructor(name: string) {
    this.name = name;
    this.internalEffect = Effect.Allow;
  }

  /**
   * Sets the policy's effect (Allow or Deny).
   * Default is Allow if not specified.
   *
   * @param effect The intended effect (Allow or Deny)
   */
  effect(effect: IntendedEffect) {
    this.internalEffect = effect;
    return this;
  }

  /**
   * Adds a condition based on the subject.
   *
   * @param pred Function that evaluates the subject and returns true if access should be granted
   * @example
   * .subjects(user => user.roles.includes('admin'))
   */
  subjects(pred: (sub: Sub) => boolean | Promise<boolean>) {
    this.subjectPred = pred;
    return this;
  }

  /**
   * Adds a condition based on the resource.
   *
   * @param pred Function that evaluates the resource and returns true if access should be granted
   * @example
   * .resources(doc => doc.isPublic)
   */
  resources(pred: (res: Res) => boolean | Promise<boolean>) {
    this.resPred = pred;
    return this;
  }

  /**
   * Adds a condition based on the action.
   *
   * @param pred Function that evaluates the action and returns true if access should be granted
   * @example
   * .actions(action => action === "read" || action === "list")
   */
  actions(pred: (action: Act) => boolean | Promise<boolean>) {
    this.actionPred = pred;
    return this;
  }

  /**
   * Adds a condition based on the context.
   *
   * @param pred Function that evaluates the context and returns true if access should be granted
   * @example
   * .context(ctx => ctx.isBusinessHours)
   */
  context(pred: (ctx: Ctx) => boolean | Promise<boolean>) {
    this.ctxPred = pred;
    return this;
  }

  /**
   * Adds a custom condition that can access all parameters.
   *
   * @param pred Function that evaluates all parameters and returns true if access should be granted
   * @example
   * .when(({subject, resource}) => subject.id === resource.ownerId)
   */
  when(pred: Condition<Sub, Res, Act, Ctx>) {
    this.extraConditionPred = pred;
    return this;
  }

  /**
   * Builds and returns the policy.
   *
   * @returns The constructed policy
   */
  build(): Policy<Sub, Res, Act, Ctx> {
    const {
      subjectPred,
      resPred,
      actionPred,
      ctxPred,
      name,
      internalEffect: effect,
      extraConditionPred,
    } = this;

    const combinedPredicate = async (
      subject: Sub,
      resource: Res,
      action: Act,
      context: Ctx
    ): Promise<boolean> => {
      return (
        (subjectPred === null || (await subjectPred(subject))) &&
        (resPred === null || (await resPred(resource))) &&
        (actionPred === null || (await actionPred(action))) &&
        (ctxPred === null || (await ctxPred(context))) &&
        (extraConditionPred === null ||
          (await extraConditionPred({ subject, resource, action, context })))
      );
    };

    const internalPolicy = {
      name,
      effect,
      predicate: combinedPredicate,
    };

    return transformInternalPolicy(internalPolicy);
  }
}

/**
 * Interface for role-based access control policies.
 *
 * @template Subject - The subject type
 * @template Resource - The resource type
 * @template Action - The action type
 * @template Context - The context type
 * @template Role - The role type (typically string)
 */
interface RoleBasedPolicy<Subject, Resource, Action, Context, Role>
  extends Policy<Subject, Resource, Action, Context> {
  requiredRolesResolver: (res: Resource, act: Action) => Role[] | Promise<Role[]>;
  userRolesResolver: (subject: Subject) => Role[] | Promise<Role[]>;
  name: string;
}

/**
 * Creates a Role-Based Access Control policy.
 * Grants access when the subject has at least one of the required roles for the resource/action.
 *
 * @template Sub - Subject type (typically a user)
 * @template Res - Resource type
 * @template Act - Action type
 * @template Ctx - Context type
 * @template Role - Role type (typically string)
 * @param requiredRolesResolver Function that returns the roles required for a resource/action
 * @param userRolesResolver Function that extracts the roles from a subject
 * @returns A RBAC policy
 *
 * @example
 * const rbacPolicy = buildRbacPolicy<User, Document, string, Context, string>({
 *   requiredRolesResolver: (doc, action) =>
 *     action === "read" ? ["user", "admin"] : ["admin"],
 *   userRolesResolver: (user) => user.roles
 * });
 */
function buildRbacPolicy<Sub, Res, Act, Ctx, Role>(
  {
    requiredRolesResolver,
    userRolesResolver,
    name = 'RbacPolicy',
  }: {
    requiredRolesResolver: (res: Res, act: Act) => Role[] | Promise<Role[]>;
    userRolesResolver: (sub: Sub) => Role[] | Promise<Role[]>;
    name?: string;
  }
): RoleBasedPolicy<Sub, Res, Act, Ctx, Role> {
  const policyType = name;
  const evaluateAccess = async ({
    subject,
    resource,
    action,
  }: {
    subject: Sub;
    resource: Res;
    action: Act;
    context: Ctx;
  }): Promise<PolicyEvalResult> => {
    const requiredRoles: Role[] = await requiredRolesResolver(resource, action);
    const userRoles: Role[] = await userRolesResolver(subject);
    const hasRole: boolean = requiredRoles.some((role) => userRoles.includes(role));
    if (hasRole) {
      return new GrantedAccessResult({
        policyType: name,
        reason: 'User has required role',
      });
    }

    return new DeniedAccessResult({
      policyType: name,
      reason: "User doesn't have required role",
    });
  };

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    requiredRolesResolver,
    userRolesResolver,
  });
}

/**
 * Interface for attribute-based access control policies.
 *
 * @template Subject - The subject type
 * @template Resource - The resource type
 * @template Action - The action type
 * @template Context - The context type
 */
interface AttributeBasedPolicy<Subject, Resource, Action, Context>
  extends Policy<Subject, Resource, Action, Context> {
  condition: Condition<Subject, Resource, Action, Context>;
}

/**
 * Creates an Attribute-Based Access Control policy.
 * Grants access based on attributes of the subject, resource, action, and context.
 *
 * @template Sub - Subject type
 * @template Res - Resource type
 * @template Act - Action type
 * @template Ctx - Context type
 * @param condition Function that evaluates attributes and returns true if access should be granted
 * @returns An ABAC policy
 *
 * @example
 * const abacPolicy = buildAbacPolicy<User, Document, string, Context>(
 *   ({subject, resource}) =>
 *     resource.isPublic || subject.id === resource.ownerId
 * );
 */
function buildAbacPolicy<Sub, Res, Act, Ctx>(
  {
    condition,
    name = 'AbacPolicy',
  }: {
    condition: Condition<Sub, Res, Act, Ctx>;
    name?: string;
  }
): AttributeBasedPolicy<Sub, Res, Act, Ctx> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = async ({
    subject,
    resource,
    action,
    context,
  }): Promise<PolicyEvalResult> => {
    const conditionMet: boolean = await condition({
      subject,
      resource,
      action,
      context,
    });

    if (conditionMet) {
      return new GrantedAccessResult({
        policyType,
        reason: 'Condition evaluated to true',
      });
    }

    return new DeniedAccessResult({
      policyType,
      reason: 'Condition evaluated to false',
    });
  };

  return Object.freeze({ name: policyType, evaluateAccess, condition });
}

/**
 * Function type for resolving relationships between subjects and resources.
 * Used in ReBAC policies to determine if a subject has a specific relationship with a resource.
 *
 * @template Subject - The subject type
 * @template Resource - The resource type
 */
type RelationshipResolver<Subject, Resource> = ({
  subject,
  resource,
  relationship,
}: {
  subject: Subject;
  resource: Resource;
  relationship: string;
}) => boolean | Promise<boolean>;

/**
 * Interface for relationship-based access control policies.
 *
 * @template Sub - The subject type
 * @template Res - The resource type
 * @template Act - The action type
 * @template Ctx - The context type
 */
interface RelationshipBasedPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly relationship: string;
  readonly resolver: RelationshipResolver<Sub, Res>;
  name: string;
}

/**
 * Creates a Relationship-Based Access Control policy.
 * Grants access based on the relationship between subject and resource.
 *
 * @template Sub - Subject type
 * @template Res - Resource type
 * @template Act - Action type
 * @template Ctx - Context type
 * @param relationship Name of the relationship (e.g., "owner", "parent", "member")
 * @param resolver Function that checks if the relationship exists
 * @returns A ReBAC policy
 *
 * @example
 * const ownerPolicy = buildRebacPolicy<User, Document, string, Context>({
 *   relationship: "owner",
 *   resolver: ({subject, resource}) => subject.id === resource.ownerId
 * });
 */
function buildRebacPolicy<Sub, Res, Act, Ctx>({
  relationship,
  resolver,
  name = 'RebacPolicy',
}: {
  relationship: string;
  resolver: RelationshipResolver<Sub, Res>;
  name?: string;
}): RelationshipBasedPolicy<Sub, Res, Act, Ctx> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = async ({
    subject,
    resource,
  }): Promise<PolicyEvalResult> => {
    const hasRelationship: boolean = await resolver({
      subject,
      resource,
      relationship,
    });

    if (hasRelationship) {
      return new GrantedAccessResult({
        policyType,
        reason: `Subject has ${relationship} relationship with resource`,
      });
    }

    return new DeniedAccessResult({
      policyType,
      reason: `Subject does not have ${relationship} relationship with resource`,
    });
  };

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    resolver,
    relationship,
  });
}

/**
 * Interface for AND combination policies.
 * Requires all child policies to grant access.
 *
 * @template Sub - The subject type
 * @template Res - The resource type
 * @template Act - The action type
 * @template Ctx - The context type
 */
interface AndPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly policies: Policy<Sub, Res, Act, Ctx>[];
  name: string;
}

/**
 * Creates a policy that requires all sub-policies to grant access.
 *
 * @template Sub - Subject type
 * @template Res - Resource type
 * @template Act - Action type
 * @template Ctx - Context type
 * @param policies Array of policies that all must grant access
 * @returns A combined AND policy
 *
 * @example
 * const policy = buildAndPolicy([adminRolePolicy, documentOwnerPolicy]);
 */
function buildAndPolicy<Sub, Res, Act, Ctx>(
  {
    policies,
    name = 'AndPolicy',
  }: {
    policies: Policy<Sub, Res, Act, Ctx>[];
    name?: string;
  }
): AndPolicy<Sub, Res, Act, Ctx> {
  if (!policies.length) {
    throw new Error('AndPolicy must have at least one policy');
  }

  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = async ({
    subject,
    resource,
    action,
    context,
  }): Promise<PolicyEvalResult> => {
    const results: PolicyEvalResult[] = [];
    for (const policy of policies) {
      const result = await policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      });
      results.push(result);

      if (!result.isGranted()) {
        return new CombinedResult({
          policyType,
          outcome: false,
          operation: CombineOp.And,
          children: results,
        });
      }
    }

    return new CombinedResult({
      policyType,
      outcome: true,
      operation: CombineOp.And,
      children: results,
    });
  };

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    policies: [...policies],
  });
}

/**
 * Interface for OR combination policies.
 * Requires any child policy to grant access.
 *
 * @template Sub - The subject type
 * @template Res - The resource type
 * @template Act - The action type
 * @template Ctx - The context type
 */
interface OrPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly policies: Policy<Sub, Res, Act, Ctx>[];
  name: string;
}

/**
 * Creates a policy that grants access if any sub-policy grants access.
 *
 * @template Sub - Subject type
 * @template Res - Resource type
 * @template Act - Action type
 * @template Ctx - Context type
 * @param policies Array of policies where any one can grant access
 * @returns A combined OR policy
 *
 * @example
 * const policy = buildOrPolicy([adminRolePolicy, documentOwnerPolicy]);
 */
function buildOrPolicy<Sub, Res, Act, Ctx>(
  {
    policies,
    name = 'OrPolicy',
  }: {
    policies: Policy<Sub, Res, Act, Ctx>[];
    name?: string;
  }
): OrPolicy<Sub, Res, Act, Ctx> {
  if (!policies.length) {
    throw new Error('OrPolicy must have at least one policy');
  }

  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = async ({
    subject,
    resource,
    action,
    context,
  }): Promise<PolicyEvalResult> => {
    const results: PolicyEvalResult[] = [];
    for (const policy of policies) {
      const result = await policy.evaluateAccess({
        subject,
        resource,
        action,
        context,
      });
      results.push(result);

      if (result.isGranted()) {
        return new CombinedResult({
          policyType,
          outcome: true,
          operation: CombineOp.Or,
          children: results,
        });
      }
    }

    return new CombinedResult({
      policyType,
      outcome: false,
      operation: CombineOp.Or,
      children: results,
    });
  };

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    policies: [...policies],
  });
}

/**
 * Interface for NOT policies that invert another policy's result.
 *
 * @template Sub - The subject type
 * @template Res - The resource type
 * @template Act - The action type
 * @template Ctx - The context type
 */
interface NotPolicy<Sub, Res, Act, Ctx> extends Policy<Sub, Res, Act, Ctx> {
  readonly policy: Policy<Sub, Res, Act, Ctx>;
  name: string;
}

/**
 * Creates a policy that inverts the result of another policy.
 *
 * @template Sub - Subject type
 * @template Res - Resource type
 * @template Act - Action type
 * @template Ctx - Context type
 * @param policy The policy to invert
 * @returns A NOT policy that grants access when the original would deny it
 *
 * @example
 * // Grant access to non-public resources
 * const policy = buildNotPolicy(publicResourcePolicy);
 */
function buildNotPolicy<Sub, Res, Act, Ctx>(
  {
    policy,
    name = 'NotPolicy',
  }: {
    policy: Policy<Sub, Res, Act, Ctx>;
    name?: string;
  }
): NotPolicy<Sub, Res, Act, Ctx> {
  const policyType = name;
  const evaluateAccess: EvaluateAccess<Sub, Res, Act, Ctx> = async ({
    subject,
    resource,
    action,
    context,
  }): Promise<PolicyEvalResult> => {
    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });

    return new CombinedResult({
      policyType,
      outcome: !result.isGranted(),
      operation: CombineOp.Not,
      children: [result],
    });
  };

  return Object.freeze({
    name: policyType,
    evaluateAccess,
    policy,
  });
}

export {
  buildAbacPolicy,
  buildAndPolicy,
  buildNotPolicy,
  buildOrPolicy,
  buildRbacPolicy,
  buildRebacPolicy,
  CombineOp,
  Effect,
  type EvaluateAccess,
  type IntendedEffect,
  PermissionChecker,
  PolicyBuilder,
  type Policy,
  type PolicyEvalResult,
};
