import { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import { Modules, ContainerRegistrationKeys } from "@medusajs/framework/utils"
import jwt from "jsonwebtoken"

export async function GET(req: MedusaRequest, res: MedusaResponse) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing or invalid authorization header." })
  }

  const token = authHeader.split(" ")[1]
  const config = req.scope.resolve(ContainerRegistrationKeys.CONFIG_MODULE)
  const jwtSecret = config.projectConfig.http.jwtSecret

  let decoded: any
  try {
    decoded = jwt.verify(token, jwtSecret as string)
  } catch {
    return res.status(401).json({ message: "Invalid or expired token." })
  }

  const authIdentityId = decoded?.auth_identity_id
  if (!authIdentityId) {
    return res.status(401).json({ message: "Invalid auth identity in token." })
  }

  // Reject if identity is already linked to a customer actor
  if (decoded?.actor_id) {
    return res.status(400).json({ message: "Identity is already linked to a customer profile." })
  }

  try {
    const authModule = req.scope.resolve(Modules.AUTH)
    const authIdentity = await authModule.retrieveAuthIdentity(authIdentityId, {
      relations: ["provider_identities"],
    })

    if (!authIdentity) {
      return res.status(404).json({ message: "Auth identity not found." })
    }

    const userMetadata = ((authIdentity as any)?.user_metadata as Record<string, any>) || {}
    const providerMetadata =
      ((authIdentity as any)?.provider_identities?.[0]?.user_metadata as Record<string, any>) || {}

    const email = userMetadata.email || providerMetadata.email || null

    if (!email) {
      return res.status(404).json({ message: "No verified email found for identity." })
    }

    const firstName =
      userMetadata.given_name || userMetadata.name || providerMetadata.given_name || providerMetadata.name || "Customer"
    const lastName = userMetadata.family_name || providerMetadata.family_name || ""

    return res.status(200).json({
      email,
      first_name: firstName,
      last_name: lastName,
    })
  } catch (error: any) {
    return res.status(500).json({ message: error.message || "Failed to retrieve identity details." })
  }
}
