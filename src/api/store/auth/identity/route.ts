import { MedusaResponse, AuthenticatedMedusaRequest } from "@medusajs/framework/http"
import { Modules } from "@medusajs/framework/utils"

export const AUTHENTICATE = true

export async function GET(req: AuthenticatedMedusaRequest, res: MedusaResponse) {
  const authContext = req.auth_context

  if (!authContext?.auth_identity_id) {
    return res.status(401).json({ message: "Unauthenticated" })
  }

  // Reject if identity is already linked to a customer actor
  if (authContext.actor_id) {
    return res.status(400).json({ message: "Identity is already linked to a customer profile." })
  }

  try {
    const authModule = req.scope.resolve(Modules.AUTH)
    const authIdentity = await authModule.retrieveAuthIdentity(authContext.auth_identity_id)

    if (!authIdentity) {
      return res.status(404).json({ message: "Auth identity not found." })
    }

    const userMetadata = ((authIdentity as any)?.user_metadata as Record<string, any>) || {}
    const email = userMetadata.email || null

    if (!email) {
      return res.status(404).json({ message: "No verified email found for identity." })
    }

    const firstName = userMetadata.given_name || userMetadata.name || "Customer"
    const lastName = userMetadata.family_name || ""

    // Return ONLY necessary fields, omitting tokens, secrets, or full metadata objects
    return res.status(200).json({
      email,
      first_name: firstName,
      last_name: lastName,
    })
  } catch (error: any) {
    return res.status(500).json({ message: error.message || "Failed to retrieve identity details." })
  }
}
