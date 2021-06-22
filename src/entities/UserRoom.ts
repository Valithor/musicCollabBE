import { Field, Int, ObjectType } from "type-graphql";
import { BaseEntity, Entity, ManyToOne, PrimaryColumn } from "typeorm";
import { Room } from "./Room";
import { User } from "./User";


@ObjectType()
@Entity()
export class UserRoom extends BaseEntity{

    @Field(() => Int)
    @PrimaryColumn()
    userId: number;

    @Field(()=> User)
    @ManyToOne(()=> User, user => user.userRooms)
    user!: User;
  
    @Field(() => Int)
    @PrimaryColumn()
    roomId!: number;

    @Field(()=>Room)
    @ManyToOne(()=> Room, room => room.userRooms)
    room: Room;
    
}