/**
 * Capability Manifest schema (FR-1.2).
 *
 * The manifest is the single framework-neutral input to AAL Core. It describes *what an
 * agent can touch* — its tools and their side-effect class, the data it can read, where
 * untrusted content enters, its identity model, and any mitigations the author declares —
 * without AAL knowing anything about the agent's framework. It extends the Agentic Product
 * Standard's `agent-capabilities.json` shape (private-data / untrusted-content / external-comms
 * legs) with the structure the toxic-flow graph (FR-3) and the runner (FR-4/5) need.
 */
import { z } from "zod";

/** Side-effect class of a declared tool. Drives severity and the toxic-flow graph. */
export const SideEffectClass = z.enum(["read", "write", "external-egress", "code-exec"]);
export type SideEffectClass = z.infer<typeof SideEffectClass>;

/** A data scope a tool can reach. `private` reads are the private-data leg of the trifecta. */
export const DataScope = z.object({
  id: z.string().min(1),
  sensitivity: z.enum(["public", "private"]),
});
export type DataScope = z.infer<typeof DataScope>;

/** A declared tool the agent can invoke. */
export const Tool = z.object({
  name: z.string().min(1),
  sideEffect: SideEffectClass,
  /** Data scopes this tool reads/writes. Empty for tools that touch no declared data. */
  dataScopes: z.array(DataScope).default([]),
  description: z.string().optional(),
});
export type Tool = z.infer<typeof Tool>;

/** A point where untrusted content enters the agent — the injection surface. */
export const UntrustedIngress = z.object({
  id: z.string().min(1),
  kind: z.enum(["retrieval", "web", "email", "tool-output", "user-upload"]),
});
export type UntrustedIngress = z.infer<typeof UntrustedIngress>;

/** The trifecta/RCE legs a declared mitigation can break. Mirrors the APS gate's `leg`. */
export const MitigationLeg = z.enum([
  "private-data",
  "untrusted-ingress",
  "external-egress",
  "code-exec",
]);
export type MitigationLeg = z.infer<typeof MitigationLeg>;

/**
 * A mitigation the author declares as breaking one leg of a dangerous composition.
 * A mitigation only counts if it names a non-empty `control` (mirrors the APS gate: a leg is
 * broken only by a declared control, never by assertion alone).
 */
export const DeclaredMitigation = z.object({
  id: z.string().min(1).optional(),
  breaks: MitigationLeg,
  control: z.string().min(1),
});
export type DeclaredMitigation = z.infer<typeof DeclaredMitigation>;

/** The agent's identity posture. Evidence for least-privilege controls in AAL Evidence. */
export const Identity = z.object({
  /** Acts on behalf of a user / another principal (delegated authority). */
  delegated: z.boolean(),
  /** Runs under scoped, least-privilege credentials rather than standing broad ones. */
  scoped: z.boolean(),
});
export type Identity = z.infer<typeof Identity>;

/** The Capability Manifest. Versioned so the schema can evolve without silent breakage. */
export const CapabilityManifest = z.object({
  manifestVersion: z.literal("0.1"),
  name: z.string().min(1),
  identity: Identity,
  tools: z.array(Tool).min(1),
  untrustedIngress: z.array(UntrustedIngress).default([]),
  declaredMitigations: z.array(DeclaredMitigation).default([]),
});
export type CapabilityManifest = z.infer<typeof CapabilityManifest>;
