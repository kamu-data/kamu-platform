import {
  Component,
  EventEmitter,
  Input,
  Output
} from "@angular/core";
import {SearchOverviewDatasetsInterface} from "../../interface/search.interface";
import AppValues from "../../common/app.values";

@Component({
  selector: 'app-repo-list',
  templateUrl: './repo-list.component.html',
  styleUrls: ['./repo-list.sass']
})
export class RepoListComponent {
  @Input() public dataSource: SearchOverviewDatasetsInterface[];
  @Input() public totalCount = 0;
  @Input() public resultUnitText: string;
  @Input() public isResultQuantity?: boolean = false;
  @Input() public isClickableRow?: boolean = false;
  @Output() public onSelectDatasetEmit: EventEmitter<string> = new EventEmitter();
  @Input() public sortOptions: {value: string, label: string, active: boolean}[];

  public momentConverDatetoLocalWithFormat(date: string): string {
    return AppValues.momentConverDatetoLocalWithFormat({date: new Date(String(date)), format: 'DD MMM YYYY', isTextDate: true});
  }
  public onSelectDataset(id: string): void {
    this.onSelectDatasetEmit.emit(id);
  }

  public searchResultQuantity(dataSource: SearchOverviewDatasetsInterface[] = []): string {
      if(!Array.isArray(dataSource)) {
        return '0';
      }
      return dataSource.length.toString();
  }

}