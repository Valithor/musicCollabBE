import { Field, Int, ObjectType } from "type-graphql";
import { BaseEntity, Column, Entity, ManyToOne, PrimaryColumn } from "typeorm";
import { Room } from "./Room";


@ObjectType()
@Entity()
export class RoomSound extends BaseEntity{

    @Field(() => Int)
    @PrimaryColumn()
    roomId: number;

    @Field(()=> Room)
    @ManyToOne(()=> Room, room => room.roomSounds)
    room: Room;
  
    @Field(()=>[String])
    @Column("text", { array: true })
    track!: string[];

    @Field()
    @Column()
    trackId!: number;
  
    
}