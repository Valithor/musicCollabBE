import { Field, Int, ObjectType } from "type-graphql";
import { BaseEntity, Column, CreateDateColumn, Entity, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { Room } from "./Room";
import { Sound } from "./Sound";
import { UserRoom } from "./UserRoom";


@ObjectType()
@Entity()
export class User extends BaseEntity{

    @Field(() => Int)
    @PrimaryGeneratedColumn()
    id!: number;

    @Field(() => String)
    @Column({ unique: true })
    email!: string;

    @Field(() => String)
    @Column({ unique: true })
    username!: string;

    @Column()
    password!: string;

    @Field(() => String, {nullable: true})
    @Column({
        type: 'text',
        nullable: true})
    location!: string | null;

    @OneToMany(()=> Room, room => room.creator)
    rooms: Promise<Room[]>;

    @OneToMany(()=> Sound, sound => sound.creator)
    sounds: Promise<Sound[]>;

    @OneToMany(()=> UserRoom, userRoom => userRoom.user)
    userRooms!: UserRoom[];
    
    @Field(() => String)
    @CreateDateColumn()
    createdAt: Date;

    @Field(() => String)
    @UpdateDateColumn()
    updatedAt: Date;

    @Column("int", { default: 0 })
    tokenVersion: number;  

}