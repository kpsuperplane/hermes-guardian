import { PLUGINS } from "@/sdk";
import { GuardianPage } from "@/GuardianPage";

// Register the Guardian tab with the host dashboard. `@/sdk` has already
// asserted the SDK + registry are present on window.
PLUGINS.register("hermes-guardian", GuardianPage);
