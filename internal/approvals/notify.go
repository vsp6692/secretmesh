// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package approvals

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/notify"
)

func (c ChangeRequest) linkPath() string {
	return fmt.Sprintf("/orgs/%s/changes?id=%s", c.OrganizationID, c.ID)
}

func (c ChangeRequest) describe() string {
	return fmt.Sprintf("%s of %q in %s (%s)", c.Operation, c.SecretName, c.EnvironmentKind, c.Classification)
}

// notifySubmittedTx tells approvers about a pending request and the security
// team and organization admins about a break-glass change.
func notifySubmittedTx(ctx context.Context, tx pgx.Tx, c ChangeRequest) error {
	org := c.OrganizationID
	if c.BreakGlass {
		security, err := notify.HoldersOf(ctx, tx, org, c.EnvironmentID, auth.PolicyManage)
		if err != nil {
			return err
		}
		admins, err := notify.OrgAdmins(ctx, tx, org)
		if err != nil {
			return err
		}
		_, err = notify.Enqueue(ctx, tx, org, notify.Event{
			Kind: notify.ChangeRequestBreakGlass, DedupeKey: "change_request.break_glass:" + c.ID.String(),
			Subject: "Break-glass change: " + c.SecretName,
			Body: fmt.Sprintf("A break-glass %s was submitted without prior approval.\nJustification: %s\nReview it after the fact.",
				c.describe(), c.Reason),
			LinkPath: c.linkPath(), Recipients: append(security, admins...),
		})
		return err
	}
	if c.Status != "pending" {
		return nil
	}
	approvers, err := notify.HoldersOf(ctx, tx, org, c.EnvironmentID, auth.ApprovalDecide)
	if err != nil {
		return err
	}
	body := fmt.Sprintf("A %s needs %d approval(s).", c.describe(), c.RequiredApprovals)
	if c.Reason != "" {
		body += "\nReason: " + c.Reason
	}
	body += "\nIt expires at " + c.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + "."
	_, err = notify.Enqueue(ctx, tx, org, notify.Event{
		Kind: notify.ChangeRequestPending, DedupeKey: "change_request.pending:" + c.ID.String(),
		Subject: "Approval requested: " + c.SecretName, Body: body,
		LinkPath: c.linkPath(), Recipients: notify.Without(approvers, c.RequestedBy),
	})
	return err
}

// NotifyOutcomeTx tells the requester how their request ended: succeeded,
// failed, rejected or expired. detail is a failure code, if any.
func NotifyOutcomeTx(ctx context.Context, tx pgx.Tx, c ChangeRequest, outcome, detail string) error {
	body := fmt.Sprintf("Your %s %s.", c.describe(), outcome)
	if detail != "" {
		body += "\nReason: " + detail
	}
	_, err := notify.Enqueue(ctx, tx, c.OrganizationID, notify.Event{
		Kind: notify.ChangeRequestCompleted, DedupeKey: "change_request.completed:" + c.ID.String(),
		Subject: fmt.Sprintf("Change %s: %s", outcome, c.SecretName), Body: body,
		LinkPath: c.linkPath(), Recipients: []uuid.UUID{c.RequestedBy},
	})
	return err
}
