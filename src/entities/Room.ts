import { Field, ObjectType } from "type-graphql";
import { BaseEntity, Column, CreateDateColumn, Entity, ManyToOne, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { RoomSound } from "./RoomSound";
import { User } from "./User";
import { UserRoom } from "./UserRoom";


@ObjectType()
@Entity()
export class Room extends BaseEntity{

    @Field()
    @PrimaryGeneratedColumn()
    id!: number;

    @Field()
    @Column()
    name!: string;

    @Field()
    @Column()
    creatorId: number;

    @Field(()=> [UserRoom])
    @OneToMany(()=> UserRoom, userRoom => userRoom.room)
    userRooms!: Promise<UserRoom[]>;

    @Field(()=> [RoomSound])
    @OneToMany(()=> RoomSound, roomSound => roomSound.room)
    roomSounds: Promise<RoomSound[]>;

    @Field()
    @ManyToOne(()=> User, user => user.rooms)
    creator: User;

    @Field(()=> String)
    @CreateDateColumn()
    createdAt: Date;

    @Field(()=>String)
    @UpdateDateColumn()
    updatedAt: Date;

  
    
}