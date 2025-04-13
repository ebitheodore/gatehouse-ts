import { describe, test, expect } from "bun:test";
import {
  buildAbacPolicy,
  buildAndPolicy,
  buildNotPolicy,
  buildOrPolicy,
  buildRbacPolicy,
  buildRebacPolicy,
  PermissionChecker,
  PolicyBuilder,
} from "../src/gatehouse";

// Define types for testing
type Subject = {
  id: string;
  roles: string[];
  groups: string[];
  department: string;
};

type Resource = {
  id: string;
  ownerId: string;
  department: string;
  isPublic: boolean;
};

type Action = "read" | "write" | "delete" | "admin";

type Context = {
  clientIp: string;
  timestamp: number;
  isEmergency: boolean;
};

describe("RBAC Policy", () => {
  test("should grant access when user has required role", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: (_, act) => {
        if (act === "read") return ["user", "admin"];
        if (act === "write") return ["editor", "admin"];
        if (act === "delete") return ["admin"];
        return ["admin"];
      },
      userRolesResolver: (sub) => sub.roles,
    });

    const result = await rbacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should deny access when user doesn't have required role", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const action: Action = "delete";
    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: (_, act) => {
        if (act === "read") return ["user", "admin"];
        if (act === "write") return ["editor", "admin"];
        if (act === "delete") return ["admin"];
        return ["admin"];
      },
      userRolesResolver: (sub) => sub.roles,
    });

    const result = await rbacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });
});

describe("ABAC Policy", () => {
  test("should grant access based on attributes", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ subject, resource }) => {
        // Allow access if resource is public or user is in the same department
        return resource.isPublic || subject.department === resource.department;
      },
    });

    const result = await abacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should deny access when attributes don't match", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "Sales",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ subject, resource }) => {
        // Allow access if resource is public or user is in the same department
        return resource.isPublic || subject.department === resource.department;
      },
    });

    const result = await abacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });
});

describe("ReBAC Policy", () => {
  test("should grant access based on relationship", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user1", // Note: same as subject id
      department: "IT",
      isPublic: false,
    };

    const action: Action = "write";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) => {
        return subject.id === resource.ownerId;
      },
    });

    const result = await rebacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should deny access when relationship doesn't exist", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Note: different from subject id
      department: "IT",
      isPublic: false,
    };

    const action: Action = "write";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) => {
        return subject.id === resource.ownerId;
      },
    });

    const result = await rebacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });
});

describe("Policy Combinators", () => {
  test("AND policy should grant access when all policies grant access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user1",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => ["admin", "user"],
      userRolesResolver: (sub) => sub.roles,
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) => subject.id === resource.ownerId,
    });

    const andPolicy = buildAndPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await andPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("AND policy should deny access when any policy denies access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Not the owner
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => ["admin", "user"],
      userRolesResolver: (sub) => sub.roles,
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) => subject.id === resource.ownerId,
    });

    const andPolicy = buildAndPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await andPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });

  test("OR policy should grant access when any policy grants access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Not the owner
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => ["admin", "user"],
      userRolesResolver: (sub) => sub.roles,
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) => subject.id === resource.ownerId,
    });

    const orPolicy = buildOrPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await orPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("OR policy should deny access when all policies deny access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"], // Not admin
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2", // Not the owner
      department: "IT",
      isPublic: true,
    };

    const action: Action = "admin"; // Requires admin role
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: (_, act) =>
        act === "admin" ? ["admin"] : ["user"],
      userRolesResolver: (sub) => sub.roles,
    });

    const rebacPolicy = buildRebacPolicy<Subject, Resource, Action, Context>({
      relationship: "owner",
      resolver: ({ subject, resource }) => subject.id === resource.ownerId,
    });

    const orPolicy = buildOrPolicy({
      policies: [rbacPolicy, rebacPolicy],
    });
    const result = await orPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });

  test("NOT policy should invert the result", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ resource }) => resource.isPublic,
    });

    // This would normally grant access since resource is public
    const normalResult = await abacPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(normalResult.isGranted()).toBe(true);

    // But the NOT policy inverts it
    const notPolicy = buildNotPolicy({
      policy: abacPolicy,
    });
    const notResult = await notPolicy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(notResult.isGranted()).toBe(false);
  });
});

describe("PolicyBuilder", () => {
  test("should create a policy with subjects condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = new PolicyBuilder<Subject, Resource, Action, Context>(
      "AdminOnly",
    )
      .subjects((sub) => sub.roles.includes("admin"))
      .build();

    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should create a policy with resources condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = new PolicyBuilder<Subject, Resource, Action, Context>(
      "PublicResourcesOnly",
    )
      .resources((res) => res.isPublic)
      .build();

    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should create a policy with action condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = new PolicyBuilder<Subject, Resource, Action, Context>(
      "ReadOnly",
    )
      .actions((act) => act === "read")
      .build();

    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should create a policy with context condition", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "admin";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: true, // Emergency override
    };

    const policy = new PolicyBuilder<Subject, Resource, Action, Context>(
      "EmergencyOverride",
    )
      .context((ctx) => ctx.isEmergency)
      .build();

    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should create a policy with multiple conditions", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = new PolicyBuilder<Subject, Resource, Action, Context>(
      "SameDepartmentReadOnly",
    )
      .actions((act) => act === "read")
      .when(
        ({ subject, resource }) => subject.department === resource.department,
      )
      .build();

    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should respect deny effect", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const policy = new PolicyBuilder<Subject, Resource, Action, Context>(
      "ExplicitDenyForAdmins",
    )
      .subjects((sub) => sub.roles.includes("admin"))
      .effect("Deny")
      .build();

    const result = await policy.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });
});

describe("PermissionChecker", () => {
  test("should grant access when any policy grants access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => ["admin"],
      userRolesResolver: (sub) => sub.roles,
    });

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ resource }) => resource.isPublic,
    });

    const checker = new PermissionChecker<Subject, Resource, Action, Context>();
    checker.addPolicy(rbacPolicy);
    checker.addPolicy(abacPolicy);

    const result = await checker.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(true);
  });

  test("should deny access when all policies deny access", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["user"],
      groups: [],
      department: "Sales",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user2",
      department: "IT",
      isPublic: false,
    };

    const action: Action = "write";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const rbacPolicy = buildRbacPolicy<
      Subject,
      Resource,
      Action,
      Context,
      string
    >({
      requiredRolesResolver: () => ["admin"],
      userRolesResolver: (sub) => sub.roles,
    });

    const abacPolicy = buildAbacPolicy<Subject, Resource, Action, Context>({
      condition: ({ subject, resource, action }) =>
        subject.department === resource.department && action === "read",
    });

    const checker = new PermissionChecker<Subject, Resource, Action, Context>();
    checker.addPolicy(rbacPolicy);
    checker.addPolicy(abacPolicy);

    const result = await checker.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });

  test("should deny access when no policies are configured", async () => {
    const subject: Subject = {
      id: "user1",
      roles: ["admin"],
      groups: [],
      department: "IT",
    };

    const resource: Resource = {
      id: "resource1",
      ownerId: "user1",
      department: "IT",
      isPublic: true,
    };

    const action: Action = "read";
    const context: Context = {
      clientIp: "127.0.0.1",
      timestamp: Date.now(),
      isEmergency: false,
    };

    const checker = new PermissionChecker<Subject, Resource, Action, Context>();
    const result = await checker.evaluateAccess({
      subject,
      resource,
      action,
      context,
    });
    expect(result.isGranted()).toBe(false);
  });
});
