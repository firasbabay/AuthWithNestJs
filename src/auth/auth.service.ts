import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SignUpDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './Schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './Schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {}

  async signup(signupData: SignUpDto) {
    const { email, password, name } = signupData;

    // Check if email is in use
    const emailInUse = await this.userModel.findOne({ email: email });
    if (emailInUse) {
      throw new BadRequestException('This email is already in use');
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user document and save in MongoDB
    const user = new this.userModel({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();
  }

  async login(loginData: LoginDto) {
    const { email, password } = loginData;
    // Find if user exist by Email
    const user = await this.userModel.findOne({ email });
    if (!user) throw new UnauthorizedException('wrong credentials');
    // Compare entered password with the existing password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) throw new UnauthorizedException('wrong credentials');
    //generate JWT token
    const Tokens = await this.generateUserTokens(user._id);
    return {
      ...Tokens,
      userId: user._id,
    };
  }

  async refreshToken(refreshToken: string) {
    // Check if the refresh token exists and not yet expired
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token)
      throw new UnauthorizedException('Invalid or expired refresh token');
    return this.generateUserTokens(token.userId);
  }
  async generateUserTokens(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      { upsert: true },
    );
  }
}
