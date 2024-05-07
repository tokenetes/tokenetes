import { NgModule } from '@angular/core';
import { HttpClientModule, HTTP_INTERCEPTORS} from '@angular/common/http';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule, ReactiveFormsModule} from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { SearchComponent } from './components/search/search.component';
import { AuthComponent } from './components/auth/auth.component';
import { AuthInterceptor } from './interceptors/auth.interceptor';
import { OrderComponent } from './components/order/order.component';
import { TransactionDetailsComponent } from './components/order/transaction-details/transaction-details.component';
import { PortfolioComponent } from './components/portfolio/portfolio.component';
import { HomeComponent } from './components/home-component/home-component.component';
import { ForbiddenModalComponent } from './components/forbidden-modal/forbidden-modal.component';

@NgModule({
  declarations: [
    AppComponent,
    SearchComponent,
    AuthComponent,
    OrderComponent,
    TransactionDetailsComponent,
    PortfolioComponent,
    HomeComponent,
    ForbiddenModalComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    FormsModule,
    ReactiveFormsModule
  ],
  providers: [    {
    provide: HTTP_INTERCEPTORS,
    useClass: AuthInterceptor,
    multi: true,
  }],
  bootstrap: [AppComponent]
})
export class AppModule { }
