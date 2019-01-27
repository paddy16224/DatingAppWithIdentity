import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanDeactivate, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';

import { MemberEditComponent } from './../members/member-edit/member-edit.component';

@Injectable({providedIn: 'root'})
export class PreventUnsavedChanges implements CanDeactivate<MemberEditComponent> {
    canDeactivate(
        component: MemberEditComponent
    ): Observable<boolean>|Promise<boolean>|boolean {
        if (component.editForm.dirty) {
            return confirm('Are you sure you want to continue? Any unsaved changes will be lost.');
        }
        return true;
    }
}
