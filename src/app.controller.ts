import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from './Guards/auth.guard';

@UseGuards(AuthGuard)
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}
  @Get()
  SomeProtectedRoute(@Req() req) {
    return { message: 'Access Ressource', userId: req.userId };
  }
}
