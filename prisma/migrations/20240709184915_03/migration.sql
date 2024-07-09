/*
  Warnings:

  - You are about to drop the column `hasheRefreshToken` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "hasheRefreshToken",
ADD COLUMN     "hashRefreshToken" TEXT;
