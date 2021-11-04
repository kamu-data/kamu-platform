import {AfterContentInit, Component, HostListener, OnInit, ViewChild} from '@angular/core';
import {AppSearchService} from "./search.service";
import {
  PageInfoInterface,
  SearchOverviewDatasetsInterface,
  SearchOverviewInterface
} from "../interface/search.interface";
import AppValues from "../common/app.values";
import {searchAdditionalButtonsEnum} from "./search.interface";
import {SearchAdditionalButtonInterface} from "../components/search-additional-buttons/search-additional-buttons.interface";
import {MatSidenav} from "@angular/material/sidenav";
import {SideNavService} from "../services/sidenav.service";
import {Router} from "@angular/router";


@Component({
  selector: 'app-search',
  templateUrl: './search.component.html',
  styleUrls: ['./search.component.sass']
})
export class SearchComponent implements OnInit, AfterContentInit {

  @ViewChild('sidenav', {static: true}) public sidenav?: MatSidenav;
  public isMobileView = false;
  public searchValue = '';
  public currentPage = 1;
  public isMinimizeSearchAdditionalButtons = false;
  public searchAdditionalButtonsData: SearchAdditionalButtonInterface[] = [{
    textButton: searchAdditionalButtonsEnum.Descission
  }, {
    textButton: searchAdditionalButtonsEnum.Reputation
  }, {
    textButton: searchAdditionalButtonsEnum.Explore,
    styleClassContainer: 'app-active-button__container',
    styleClassButton: 'app-active-button'
  }, {
    textButton: searchAdditionalButtonsEnum.DeriveForm,
    styleClassContainer: 'app-active-button__container',
    styleClassButton: 'app-active-button'
  }];

  public tableData: {
    tableSource: SearchOverviewDatasetsInterface[],
    isResultQuantity: boolean,
    resultUnitText: string,
    isClickableRow: boolean,
    pageInfo: PageInfoInterface,
    totalCount: number
  };
  public searchData: SearchOverviewDatasetsInterface[] = [];
  private _window: Window;

  @HostListener('window:resize', ['$event'])
  private checkWindowSize(): void {
    this.isMinimizeSearchAdditionalButtons = AppValues.isMobileView();
    this.isMobileView = AppValues.isMobileView();

    if (AppValues.isMobileView()) {
      this.sidenavService.close();
    } else {
      this.sidenavService.open();
    }
  }

  constructor(
      private router: Router,
      private appSearchService: AppSearchService,
      private sidenavService: SideNavService) {
      this._window = window;
  }

  public ngAfterContentInit(): void {
    this.tableData.tableSource = this.searchData;

    if (this._window.location.search.split('?id=').length > 1) {
      const currentId: string = this._window.location.search.split('?id=')[1].split('&')[0];
      this.onSearch(currentId || "");
    } else {
      this.onSearch("");
    }
  }


  public ngOnInit(): void {
    if(this.sidenav) {
      this.sidenavService.setSidenav(this.sidenav);
      this.checkWindowSize();
    }

    this.initTableData();

    if (this._window.location.search.split('?id=').length > 1) {
      const currentId: string = this._window.location.search.split('?id=')[1].split('&')[0];
      this.onSearch(currentId || "");
    } else {
      this.onSearch("");
    }

    this.appSearchService.onSearchChanges.subscribe((value: string) => {
      this.searchValue = value;
      this.onSearch(value);
    })

    this.appSearchService.onSearchDataChanges.subscribe((data: SearchOverviewInterface) => {
      this.tableData.tableSource = data.dataset;
      this.tableData.pageInfo = data.pageInfo;
      this.tableData.totalCount = data.totalCount;
      this.currentPage = data.currentPage;
    });
  }

  private initTableData(): void {
    this.tableData = {
      tableSource: this.searchData,
      resultUnitText: 'dataset results',
      isResultQuantity: true,
      isClickableRow: true,
      pageInfo: {
        hasNextPage: false,
        hasPreviousPage: false,
        totalPages: 1
      },
      totalCount: 0
    };
  }

  public onPageChange(params: {currentPage: number, isClick: boolean}): void {
    this.currentPage = params.currentPage;
    this.onSearch(this.searchValue, params.currentPage - 1)
  }

  public onSelectDataset(id: string): void {
    this.router.navigate(['/dataset-view'], {queryParams: {id, type: AppValues.urlDatasetViewOverviewType}});
  }


  public onClickSearchAdditionalButton(method: string) {
    if (method === searchAdditionalButtonsEnum.DeriveForm) {
      this.onClickDeriveForm();
    }
    if (method === searchAdditionalButtonsEnum.Reputation) {
      this.onClickReputation();
    }
    if (method === searchAdditionalButtonsEnum.Explore) {
      this.onClickExplore();
    }
    if (method === searchAdditionalButtonsEnum.Descission) {
      this.onClickDescission();
    }
  }

  private onClickDeriveForm() {
    console.log('onClickDeriveForm');
  }
  private onClickExplore() {
    console.log('onClickExplore');
  }
  private onClickReputation() {
    console.log('onClickReputation');
  }
  private onClickDescission() {
    console.log('onClickDescission');
  }

  public onSearch(searchValue: string, page?: number): void {
    this.appSearchService.search(searchValue, page);
  }

}
