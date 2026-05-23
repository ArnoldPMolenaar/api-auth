package controllers

import (
	"api-auth/main/src/claims"
	"api-auth/main/src/models"
	"api-auth/main/src/services"

	errorutil "github.com/ArnoldPMolenaar/api-utils/errors"
	util "github.com/ArnoldPMolenaar/api-utils/utils"
	"github.com/gofiber/fiber/v3"
)

// accessClaimsFromContext extracts and validates access claims from Fiber locals.
func accessClaimsFromContext(c fiber.Ctx) (*claims.AccessClaims, error) {
	claim := c.Locals("claims")
	if claim == nil {
		return nil, errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Claims not found.")
	}

	accessClaims, ok := claim.(*claims.AccessClaims)
	if !ok {
		return nil, errorutil.Response(c, fiber.StatusUnauthorized, errorutil.Unauthorized, "Invalid claims type.")
	}

	return accessClaims, nil
}

// getUserByIDOrResponse fetches a user and maps query/not-found errors to API responses.
func getUserByIDOrResponse(c fiber.Ctx, userID uint, includeDeleted ...bool) (*models.User, error) {
	user, err := services.GetUserByID(userID, includeDeleted...)
	if err != nil {
		return nil, errorutil.Response(c, fiber.StatusInternalServerError, errorutil.QueryError, err.Error())
	}
	if user.ID == 0 {
		return nil, errorutil.Response(c, fiber.StatusNotFound, errorutil.NotFound, "User not found.")
	}

	return &user, nil
}

// ensureUserHasAnyAllowedApp checks if the target user shares at least one allowed app.
func ensureUserHasAnyAllowedApp(c fiber.Ctx, user *models.User, accessClaims *claims.AccessClaims, status int, code, message string) error {
	allowedApps := claimAllowedApps(accessClaims)

	if isAllowedApp(allowedApps, user.AppName) {
		return nil
	}
	for i := range user.AppRecipes {
		if isAllowedApp(allowedApps, user.AppRecipes[i].AppName) {
			return nil
		}
	}
	for i := range user.AppRoles {
		if isAllowedApp(allowedApps, user.AppRoles[i].AppName) {
			return nil
		}
	}

	return errorutil.Response(c, status, code, message)
}

// ensureUserHasOnlyAllowedApps checks if all target user apps are inside the caller scope.
func ensureUserHasOnlyAllowedApps(c fiber.Ctx, user *models.User, accessClaims *claims.AccessClaims, status int, code, message string) error {
	allowedApps := claimAllowedApps(accessClaims)

	if len(user.AppRecipes) == 0 && len(user.AppRoles) == 0 {
		if !isAllowedApp(allowedApps, user.AppName) {
			return errorutil.Response(c, status, code, message)
		}
		return nil
	}

	for i := range user.AppRecipes {
		if !isAllowedApp(allowedApps, user.AppRecipes[i].AppName) {
			return errorutil.Response(c, status, code, message)
		}
	}
	for i := range user.AppRoles {
		if !isAllowedApp(allowedApps, user.AppRoles[i].AppName) {
			return errorutil.Response(c, status, code, message)
		}
	}

	return nil
}

func claimAllowedApps(accessClaims *claims.AccessClaims) map[string]struct{} {
	apps := make(map[string]struct{}, len(accessClaims.Apps)+1)
	for appName := range accessClaims.Apps {
		pascalCase := util.CamelcaseToPascalCase(appName)
		apps[pascalCase] = struct{}{}
	}
	if accessClaims.App != "" {
		apps[accessClaims.App] = struct{}{}
	}

	return apps
}

func isAllowedApp(allowedApps map[string]struct{}, app string) bool {
	_, ok := allowedApps[app]
	return ok
}


