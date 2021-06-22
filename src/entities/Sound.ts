import { Field, Int, ObjectType } from "type-graphql";
import { BaseEntity, Column, CreateDateColumn, Entity, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { User } from "./User";


@ObjectType()
@Entity()
export class Sound extends BaseEntity{

    @Field(()=>Int)
    @PrimaryGeneratedColumn()
    id!: number;

    @Field()
    @Column()
    path!: string;

    @Field(()=>Int)
    @Column()
    creatorId: number;

    @Field(()=>User)
    @ManyToOne(()=> User, user => user.sounds)
    creator: User;

    @Field(()=> String)
    @CreateDateColumn()
    createdAt: Date;

    @Field(()=>String)
    @UpdateDateColumn()
    updatedAt: Date;

  
    
}