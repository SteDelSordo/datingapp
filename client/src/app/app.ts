import { HttpClient } from '@angular/common/http';
import { Component, inject, OnInit, signal } from '@angular/core';
import { lastValueFrom } from 'rxjs/internal/lastValueFrom';

@Component({
  selector: 'app-root',
  imports: [],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit {
  private http = inject(HttpClient);
  protected title = ('L0ve4All');
  protected members = signal<any>([]);

  async ngOnInit() {
    this.members.set(await this.getMembers());
  }

  async getMembers() {
    try {

      return lastValueFrom(this.http.get('https://localhost:5001/api/members'));

    } catch (error) {

      console.error(error);
      throw error;

    }


  }

}
