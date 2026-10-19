// Guided choices of the manifest builder (`<CrdForm>`, @weebo/operator-docs):
// some kinds accept mutually exclusive ways of doing one thing (a service
// account's credentials in a Secret or in Vault). The schema can only say
// "these are all optional"; this table says which go together, so the form
// asks "how?" first and shows only the matching fields.
//
// Field names are `spec` keys. A kind not listed here gets the plain form.
// Keep them in sync with the CRDs when renaming a field.

import type { CrdChoices } from "@weebo/operator-docs/crd-form";

export const CHOICES: CrdChoices = {
  StalwartServiceAccount: [
    {
      id: "delivery",
      label: "Mail sent to it",
      options: [
        { id: "noreply", label: "Dropped", hint: "A no-reply sender: delivery to the account is disabled.", fields: [] },
        { id: "receive", label: "Delivered", hint: "The account also receives mail (bounces, replies).", fields: [], set: { receive: true } },
      ],
    },
    {
      id: "target",
      label: "Credentials in",
      options: [
        {
          id: "default",
          label: "Default Secret",
          hint: "One Kubernetes Secret named after the CR, in its namespace (the instance's default backend must be kubernetes).",
          fields: [],
        },
        {
          id: "explicit",
          label: "Secret targets",
          hint: "Kubernetes Secrets you name, and/or the Vault target `smtp` (no path: <pathPrefix>/<namespace>/smtp).",
          fields: ["secretTargets"],
          require: ["secretTargets"],
        },
      ],
    },
  ],
  StalwartAccount: [
    {
      id: "state",
      label: "State",
      options: [
        { id: "active", label: "Active", hint: "Logins, sending and delivery work.", fields: [] },
        {
          id: "locked",
          label: "Locked",
          hint: "Every login (App Passwords included), sending and delivery refused; the mailbox, its address and its App Passwords kept.",
          fields: [],
          set: { state: "Locked" },
        },
      ],
    },
  ],
};
