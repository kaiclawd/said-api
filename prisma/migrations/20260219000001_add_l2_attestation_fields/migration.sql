-- AlterTable: Add L2 attestation and activity tracking fields
ALTER TABLE "Agent" ADD COLUMN IF NOT EXISTS "l2AttestationMethod" TEXT;
ALTER TABLE "Agent" ADD COLUMN IF NOT EXISTS "registrationSource" TEXT;
ALTER TABLE "Agent" ADD COLUMN IF NOT EXISTS "activityCount" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Agent" ADD COLUMN IF NOT EXISTS "lastActiveAt" TIMESTAMP(3);
