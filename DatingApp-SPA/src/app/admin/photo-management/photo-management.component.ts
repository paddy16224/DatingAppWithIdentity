import { Photo } from './../../_model/photo';
import { AlertifyService } from './../../_services/alertify.service';
import { AdminService } from './../../_services/admin.service';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-photo-management',
  templateUrl: './photo-management.component.html',
  styleUrls: ['./photo-management.component.css']
})
export class PhotoManagementComponent implements OnInit {
  photos: any;

  constructor(private adminService: AdminService, private alertify: AlertifyService) { }

  ngOnInit() {
    this.getPhotosForApproval();
  }

  getPhotosForApproval() {
    this.adminService.getPhotosForApproval().subscribe((photos) => {
      this.photos = photos;
    }, error => {
      this.alertify.error(error);
    });
  }

  approvePhoto(photoId) {
    this.adminService.approvePhoto(photoId).subscribe(() => {
      this.photos.splice(this.photos.findIndex(p => p.id === photoId), 1);
    }, error => {
      this.alertify.error(error);
    });
  }

  rejectPhoto(photoId) {
    this.adminService.rejectPhoto(photoId).subscribe(() => {
      this.photos.splice(this.photos.findIndex(p => p.id === photoId), 1);
    }, error => {
      this.alertify.error(error);
    });
  }

}
