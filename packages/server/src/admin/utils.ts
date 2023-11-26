import { forbidden, OperationOutcomeError, badRequest, allOk } from '@medplum/core';
import { NextFunction, Request, Response } from 'express';
import { getAuthenticatedContext } from '../context';
import { validationResult } from 'express-validator';
import { invalidRequest, sendOutcome } from '../fhir/outcomes';
import { getUserByEmail } from '../oauth/utils';
import { setPassword } from '../auth/setpassword';

/**
 * Verifies that the current user is a project admin.
 * @param req - The request.
 * @param res - The response.
 * @param next - The next handler function.
 */
export async function verifyProjectAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  const ctx = getAuthenticatedContext();
  if (ctx.project.superAdmin || ctx.membership.admin) {
    next();
  } else {
    next(new OperationOutcomeError(forbidden));
  }
}

export async function forceSetPassword(req: Request, res: Response) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    sendOutcome(res, invalidRequest(errors));
    return;
  }

  const user = await getUserByEmail(req.body.email, req.body.projectId);
  if (!user) {
    sendOutcome(res, badRequest('User not found'));
    return;
  }

  await setPassword(user, req.body.password as string);
  sendOutcome(res, allOk);
}
