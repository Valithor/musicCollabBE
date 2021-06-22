import {MigrationInterface, QueryRunner} from "typeorm";

export class Initial1623602943168 implements MigrationInterface {
    name = 'Initial1623602943168'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "room_sound" ("roomId" integer NOT NULL, "track" text array NOT NULL, "trackId" integer NOT NULL, CONSTRAINT "PK_5cdc907cf6cef5eba851b0d7e4f" PRIMARY KEY ("roomId"))`);
        await queryRunner.query(`CREATE TABLE "sound" ("id" SERIAL NOT NULL, "path" character varying NOT NULL, "creatorId" integer NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_042a7f5e448107b2fd0eb4dfe8c" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "user_room" ("userId" integer NOT NULL, "roomId" integer NOT NULL, CONSTRAINT "PK_fac19050e864b2115d97253cb8e" PRIMARY KEY ("userId", "roomId"))`);
        await queryRunner.query(`CREATE TABLE "user" ("id" SERIAL NOT NULL, "email" character varying NOT NULL, "username" character varying NOT NULL, "password" character varying NOT NULL, "location" text, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "UQ_e12875dfb3b1d92d7d7c5377e22" UNIQUE ("email"), CONSTRAINT "UQ_78a916df40e02a9deb1c4b75edb" UNIQUE ("username"), CONSTRAINT "PK_cace4a159ff9f2512dd42373760" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "room" ("id" SERIAL NOT NULL, "name" character varying NOT NULL, "creatorId" integer NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_c6d46db005d623e691b2fbcba23" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "room_sound" ADD CONSTRAINT "FK_5cdc907cf6cef5eba851b0d7e4f" FOREIGN KEY ("roomId") REFERENCES "room"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "sound" ADD CONSTRAINT "FK_266b7078efd30e6007b169d0db6" FOREIGN KEY ("creatorId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "user_room" ADD CONSTRAINT "FK_6a20569bb399fa9feb2f0dd683a" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "user_room" ADD CONSTRAINT "FK_a074a2b9287d9941dcf5144bffe" FOREIGN KEY ("roomId") REFERENCES "room"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "room" ADD CONSTRAINT "FK_86e40e0afb08286884be0e6f38b" FOREIGN KEY ("creatorId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "room" DROP CONSTRAINT "FK_86e40e0afb08286884be0e6f38b"`);
        await queryRunner.query(`ALTER TABLE "user_room" DROP CONSTRAINT "FK_a074a2b9287d9941dcf5144bffe"`);
        await queryRunner.query(`ALTER TABLE "user_room" DROP CONSTRAINT "FK_6a20569bb399fa9feb2f0dd683a"`);
        await queryRunner.query(`ALTER TABLE "sound" DROP CONSTRAINT "FK_266b7078efd30e6007b169d0db6"`);
        await queryRunner.query(`ALTER TABLE "room_sound" DROP CONSTRAINT "FK_5cdc907cf6cef5eba851b0d7e4f"`);
        await queryRunner.query(`DROP TABLE "room"`);
        await queryRunner.query(`DROP TABLE "user"`);
        await queryRunner.query(`DROP TABLE "user_room"`);
        await queryRunner.query(`DROP TABLE "sound"`);
        await queryRunner.query(`DROP TABLE "room_sound"`);
    }

}
