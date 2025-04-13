---
title: Examples
group: Documents
category: Guides
---

# Gatehouse-TS Usage Examples

This document provides practical examples of how to use the Gatehouse-TS library to implement various authorization patterns.

## 1. Basic Setup

First, let's define the types we'll use for our subjects (users), resources (documents), actions, and context.

```typescript
import {
  PermissionChecker,
  PolicyBuilder,
  buildRbacPolicy,
  buildAbacPolicy,
  buildRebacPolicy,
  buildAndPolicy,
  buildOrPolicy,
  buildNotPolicy,
  Effect,
} from 'gatehouse-ts';

// Define types for your application
type User = {
  id: string;
  roles: string[]; // e.g., ["admin", "editor", "viewer"]
  department: string;
};

type Document = {
  id: string;
  ownerId: string;
  isPublic: boolean;
  requiredDepartment: string | null; // e.g., "HR", "Engineering"
};

type Action = "read" | "write" | "delete" | "comment";

type RequestContext = {
  ipAddress: string;
  timestamp: Date;
};

// Helper function to create sample data
const createUser = (id: string, roles: string[], department: string): User => ({ id, roles, department });
const createDocument = (id: string, ownerId: string, isPublic: boolean, requiredDepartment: string | null = null): Document => ({
  id, ownerId, isPublic, requiredDepartment
});

// Sample data
const adminUser = createUser("user-admin", ["admin"], "IT");
const editorUser = createUser("user-editor", ["editor"], "Marketing");
const viewerUser = createUser("user-viewer", ["viewer"], "Sales");
const guestUser = createUser("user-guest", [], "External");

const publicDoc = createDocument("doc-public", editorUser.id, true);
const privateDoc = createDocument("doc-private", editorUser.id, false);
const hrDoc = createDocument("doc-hr", adminUser.id, false, "HR");

const sampleContext: RequestContext = { ipAddress: "192.168.1.100", timestamp: new Date() };
```

Now, create an instance of `PermissionChecker`:

```typescript
const permissionChecker = new PermissionChecker<User, Document, Action, RequestContext>();
```

## 2. Role-Based Access Control (RBAC)

A RBAC policy grants access based on the roles assigned to the subject.

**Example:** Allow users with the _"editor"_ or _"admin"_ role to write to any document, and users with _"viewer"_, _"editor"_, or _"admin"_ roles to read all documents.

```typescript
const rbacPolicy = buildRbacPolicy<User, Document, Action, RequestContext, string>({
  name: "Standard RBAC Policy",
  requiredRolesResolver: (resource, action) => {
    // This function determines which roles are needed for a given resource and action.
    // Here, it's simplified and only depends on the action.
    switch (action) {
      case "read":
        return ["viewer", "editor", "admin"];
      case "write":
      case "comment":
        return ["editor", "admin"];
      case "delete":
        return ["admin"];
      default:
        return []; // Deny unknown actions
    }
  },
  userRolesResolver: (subject) => {
    // This function extracts the roles from the subject (User).
    return subject.roles;
  },
});

// Add the policy to the checker
permissionChecker.addPolicy(rbacPolicy);

// --- Evaluation ---
// Editor tries to write to a private doc (Allowed by RBAC)
let result = await permissionChecker.evaluateAccess({
  subject: editorUser,
  resource: privateDoc,
  action: "write",
  context: sampleContext,
});
console.log(`Editor write privateDoc: ${result.isGranted()}`); // Output: true

// Viewer tries to write to a public doc (Denied by RBAC)
result = await permissionChecker.evaluateAccess({
  subject: viewerUser,
  resource: publicDoc,
  action: "write",
  context: sampleContext,
});
console.log(`Viewer write publicDoc: ${result.isGranted()}`); // Output: false
// To see *why* it was denied, use the trace:
// console.log(result.getDisplayTrace());
```

**Explanation:**

*   `buildRbacPolicy` creates an RBAC policy.
*   `requiredRolesResolver` defines the roles needed for an action (and potentially resource).
*   `userRolesResolver` tells the policy how to find the roles a user possesses.
*   The `PermissionChecker` evaluates policies in the order they are added. If `rbacPolicy` grants access, the evaluation stops.

## 3. Attribute-Based Access Control (ABAC)

An ABAC policy makes decisions based on attributes of the subject, resource, action, and context.

**Example:** Allow anyone to "read" a document if its `isPublic` attribute is true.

```typescript
const publicReadPolicy = buildAbacPolicy<User, Document, Action, RequestContext>({
  name: "Public Document Read Access",
  condition: ({ resource, action }) => {
    // This function evaluates the condition based on provided attributes.
    return action === "read" && resource.isPublic;
  },
});

// Add this policy *before* the RBAC policy if you want it to take precedence
// for public reads. Let's create a new checker for clarity.
const checkerWithAbacFirst = new PermissionChecker<User, Document, Action, RequestContext>();
checkerWithAbacFirst.addPolicy(publicReadPolicy); // Public reads checked first
checkerWithAbacFirst.addPolicy(rbacPolicy);    // Then fall back to RBAC

// --- Evaluation ---
// Guest tries to read a public document (Allowed by ABAC)
result = await checkerWithAbacFirst.evaluateAccess({
  subject: guestUser, // Has no roles
  resource: publicDoc,
  action: "read",
  context: sampleContext,
});
console.log(`Guest read publicDoc: ${result.isGranted()}`); // Output: true

// Guest tries to read a private document (Denied by ABAC, then Denied by RBAC)
result = await checkerWithAbacFirst.evaluateAccess({
  subject: guestUser,
  resource: privateDoc,
  action: "read",
  context: sampleContext,
});
console.log(`Guest read privateDoc: ${result.isGranted()}`); // Output: false
// console.log(result.getDisplayTrace()); // Shows both policies denying
```

**Explanation:**

*   `buildAbacPolicy` creates an ABAC policy based on a `condition` function.
*   The `condition` function returns `true` if access should be granted based on the attributes.
*   The order policies are added to `PermissionChecker` matters. Here, `publicReadPolicy` is checked first. If it grants access (public doc, read action), the check succeeds immediately. Otherwise, `rbacPolicy` is evaluated.

## 4. Relationship-Based Access Control (ReBAC)

ReBAC policies grant access based on the relationship between the subject and the resource (e.g., owner, member).

**Example:** Allow a user to "delete" a document only if they are the owner.

```typescript
const ownerDeletePolicy = buildRebacPolicy<User, Document, Action, RequestContext>({
  name: "Owner Delete Policy",
  relationship: "owner", // Name of the relationship
  resolver: ({ subject, resource }) => {
    // This function checks if the relationship exists.
    return subject.id === resource.ownerId;
  },
});

// We only want this policy to apply to the "delete" action.
// We can wrap it using PolicyBuilder or an AND policy. Let's use PolicyBuilder.
const ownerCanDeletePolicy = new PolicyBuilder<User, Document, Action, RequestContext>("OwnerCanDelete")
  .actions(action => action === "delete") // Only applies to delete actions
  .when(async ({ subject, resource, action, context }) => {
      // Evaluate the original ReBAC policy *only* if the action is delete
      const rebacResult = await ownerDeletePolicy.evaluateAccess({ subject, resource, action, context });
      return rebacResult.isGranted();
  })
  .build();


// Let's add this to a fresh checker
const checkerWithRebac = new PermissionChecker<User, Document, Action, RequestContext>();
checkerWithRebac.addPolicy(ownerCanDeletePolicy);
checkerWithRebac.addPolicy(rbacPolicy); // RBAC as fallback

// --- Evaluation ---
// The editor tries to delete their own document (Allowed by ReBAC wrapper)
result = await checkerWithRebac.evaluateAccess({
  subject: editorUser,
  resource: privateDoc, // Owned by editorUser
  action: "delete",
  context: sampleContext,
});
console.log(`Editor delete own doc: ${result.isGranted()}`); // Output: true

// The admin tries to delete the editor's document
// (Denied by ReBAC wrapper, but Allowed by RBAC fallback)
result = await checkerWithRebac.evaluateAccess({
  subject: adminUser,
  resource: privateDoc, // Owned by editorUser
  action: "delete",
  context: sampleContext,
});
console.log(`Admin delete editor's doc: ${result.isGranted()}`); // Output: true
// console.log(result.getDisplayTrace()); // Shows ReBAC fail, RBAC grant

// The editor tries to delete the admin's document (Denied by ReBAC, Denied by RBAC)
result = await checkerWithRebac.evaluateAccess({
    subject: editorUser,
    resource: hrDoc, // Owned by adminUser
    action: "delete",
    context: sampleContext,
});
console.log(`Editor delete admin's doc: ${result.isGranted()}`); // Output: false
```

**Explanation:**

*   `buildRebacPolicy` defines access based on a named `relationship`.
*   The `resolver` function determines if the subject has the specified relationship with the resource.
*   We used `PolicyBuilder` to restrict the ReBAC check only to the "delete" action, ensuring it doesn't interfere with other actions. The `when` clause evaluates the original `ownerDeletePolicy`.
*   The `PermissionChecker` first tries `ownerCanDeletePolicy`. If that denies, it falls back to `rbacPolicy`.

## 5. Using PolicyBuilder

`PolicyBuilder` provides a fluent API to create complex, custom policies by combining conditions on subject, resource, action, context, and custom logic.

**Example:** Allow users in the "HR" department to "read" documents marked for the "HR" department, but only during business hours (e.g., 9-5).

```typescript
// Assume a helper function for business hours check
const isBusinessHours = (context: RequestContext): boolean => {
  const hour = context.timestamp.getHours();
  return hour >= 9 && hour < 17;
};

const hrAccessPolicy = new PolicyBuilder<User, Document, Action, RequestContext>("HR Department Access")
  .subjects(subject => subject.department === "HR") // Subject must be in HR
  .resources(resource => resource.requiredDepartment === "HR") // Resource must be for HR
  .actions(action => action === "read") // Action must be "read"
  .context(ctx => isBusinessHours(ctx)) // Must be business hours
  .build();

// Add to a checker
const checkerWithBuilder = new PermissionChecker<User, Document, Action, RequestContext>();
checkerWithBuilder.addPolicy(hrAccessPolicy);
checkerWithBuilder.addPolicy(rbacPolicy); // Fallback

// --- Evaluation ---
const hrUser = createUser("user-hr", ["viewer"], "HR");
const outsideHoursContext: RequestContext = { ipAddress: "192.168.1.101", timestamp: new Date(2023, 10, 15, 18, 0, 0) }; // 6 PM

// HR User reading HR Doc during business hours (Allowed by Builder)
result = await checkerWithBuilder.evaluateAccess({
  subject: hrUser,
  resource: hrDoc,
  action: "read",
  context: sampleContext, // Assumed to be within business hours
});
console.log(`HR User read HR Doc (Business Hours): ${result.isGranted()}`); // Output: true

// HR User reading HR Doc outside business hours (Denied by Builder, Denied by RBAC)
result = await checkerWithBuilder.evaluateAccess({
  subject: hrUser,
  resource: hrDoc,
  action: "read",
  context: outsideHoursContext,
});
console.log(`HR User read HR Doc (Outside Hours): ${result.isGranted()}`); // Output: false

// Non-HR User reading HR Doc (Denied by Builder, Denied by RBAC)
result = await checkerWithBuilder.evaluateAccess({
  subject: editorUser, // Not in HR dept
  resource: hrDoc,
  action: "read",
  context: sampleContext,
});
console.log(`Editor read HR Doc: ${result.isGranted()}`); // Output: false
```

**Explanation:**

*   `PolicyBuilder` starts with a name.
*   Methods like `.subjects()`, `.resources()`, `.actions()`, and `.context()` add conditions. All conditions must pass for the policy predicate to be true. Each of those can be called once, and return the same `PolicyBuilder` instance, giving you a fluent API to build a custom policy.
*   `.when()` allows adding a more complex condition involving multiple parameters.
*   `.effect(Effect.Deny)` can be used to create policies that explicitly deny access if their conditions match.
*   `.build()` constructs the final `Policy` instance, which can be added to any `PermissionChecker` instance.

## 6. Combining Policies

You can combine existing policies using logical operators: AND, OR, NOT.

**Example:** Grant "comment" access if the user is the owner **AND** the document is not public **OR** if the user is an "admin".

```typescript
// Policy 1: Is the user the owner? (ReBAC)
const ownerPolicy = buildRebacPolicy<User, Document, Action, RequestContext>({
    name: "IsOwner",
    relationship: "owner",
    resolver: ({ subject, resource }) => subject.id === resource.ownerId
});

// Policy 2: Is the document private? (ABAC)
const isPrivatePolicy = buildAbacPolicy<User, Document, Action, RequestContext>({
    name: "IsPrivate",
    condition: ({ resource }) => !resource.isPublic
});

// Policy 3: Is the user an admin? (RBAC simplified)
const isAdminPolicy = buildRbacPolicy<User, Document, Action, RequestContext, string>({
    name: "IsAdmin",
    requiredRolesResolver: () => ["admin"], // Requires admin role regardless of resource/action
    userRolesResolver: (subject) => subject.roles
});

// Combine: (Owner AND Private)
const ownerAndPrivatePolicy = buildAndPolicy({
    name: "OwnerAndPrivate",
    policies: [ownerPolicy, isPrivatePolicy]
});

// Combine: (Owner AND Private) OR Admin
const finalCommentPolicy = buildOrPolicy({
    name: "CommentAccessLogic",
    policies: [ownerAndPrivatePolicy, isAdminPolicy]
});

// Wrap to apply only to "comment" action
const restrictedCommentPolicy = new PolicyBuilder<User, Document, Action, RequestContext>("RestrictedCommentPolicy")
    .actions(action => action === "comment")
    .when(async ({ subject, resource, action, context }) => {
        const evalResult = await finalCommentPolicy.evaluateAccess({ subject, resource, action, context });
        return evalResult.isGranted();
    })
    .build();

// Add to checker
const checkerWithCombined = new PermissionChecker<User, Document, Action, RequestContext>();
checkerWithCombined.addPolicy(restrictedCommentPolicy);
checkerWithCombined.addPolicy(rbacPolicy); // Standard fallback

// --- Evaluation ---
// Owner tries to comment on their private doc (Allowed: Owner AND Private)
result = await checkerWithCombined.evaluateAccess({
  subject: editorUser,
  resource: privateDoc, // Private, owned by editor
  action: "comment",
  context: sampleContext,
});
console.log(`Owner comment private doc: ${result.isGranted()}`); // Output: true

// Owner tries to comment on their public doc (Denied: Not Private)
result = await checkerWithCombined.evaluateAccess({
  subject: editorUser,
  resource: publicDoc, // Public, owned by editor
  action: "comment",
  context: sampleContext,
});
console.log(`Owner comment public doc: ${result.isGranted()}`); // Output: false (Falls back to RBAC, also grants) -> Check Trace!

// Admin tries to comment on a private doc they don't own (Allowed: Is Admin)
result = await checkerWithCombined.evaluateAccess({
  subject: adminUser,
  resource: privateDoc, // Private, owned by editor
  action: "comment",
  context: sampleContext,
});
console.log(`Admin comment private doc: ${result.isGranted()}`); // Output: true

// Viewer tries to comment on a private doc (Denied: Not Owner/Private, Not Admin)
result = await checkerWithCombined.evaluateAccess({
  subject: viewerUser,
  resource: privateDoc,
  action: "comment",
  context: sampleContext,
});
console.log(`Viewer comment private doc: ${result.isGranted()}`); // Output: false (Falls back to RBAC, denies)
```

**Explanation:**

*   `buildAndPolicy` requires all its child policies to grant access.
*   `buildOrPolicy` requires at least one of its child policies to grant access.
*   `buildNotPolicy` inverts the result of its child policy (Grant -> Deny, Deny -> Grant).
*   Policies can be nested to create complex logic.
*   Using `PolicyBuilder` to restrict the combined logic to the "comment" action prevents it from interfering with other actions like "read" or "write".

## 7. Evaluation and Tracing

When `permissionChecker.evaluateAccess` is called:

1.  It iterates through its added policies in order.
2.  For each policy, it calls `policy.evaluateAccess`.
3.  If _any_ policy grants access (`isGranted() === true`), the checker "short-circuits" and returns a _Granted_ `AccessEvaluation` instance. If all of them fail, the checker returns a _Denied_ `AccessEvaluation`.

The returned `AccessEvaluation` object contains:

*   `isGranted()`: Returns `true` or `false`.
*   `reason`: A high-level reason for denial, or `null` if granted.
*   `policyType`: The name of the policy that granted access, or `null` if denied.
*   `getDisplayTrace()`: Returns a detailed, formatted string showing the evaluation path, including which policies were checked and their individual outcomes. This is useful for debugging complex authorization logic that combines many different policies.

```typescript
result = await checkerWithCombined.evaluateAccess({
  subject: viewerUser,
  resource: privateDoc,
  action: "comment",
  context: sampleContext,
});

if (result.isGranted()) {
  console.log("Access Granted!");
  // Optionally log the granting policy type: console.log(result.policyType);
} else {
  console.log("Access Denied.");
  // Print the detailed trace to understand why
  console.log(result.getDisplayTrace());
}
```

This trace helps diagnose why access was denied (or granted) by showing the results of each policy and combinator in the evaluation chain.
