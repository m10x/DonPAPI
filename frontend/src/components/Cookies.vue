<template>
  <div class="container">
    <h1>Cookies</h1>
    <div class="hide-secrets" @click="hideSecrets=!hideSecrets">
      <input type="checkbox" v-model="hideSecrets">Hide Passwords</input>
    </div>
    <hr><br><br>
    <div class="buttons">
      <div class="functionalities-buttons">
        <button @click="copyCookies" type="button" class="btn btn-sm" title="Copy checked cookies to JavaScript code, in order to inject them into your browser">Copy</button>
        <button style="margin-left: 1rem;" @click="exportCookiesToCsv();" type="button" title="Export checked items to csv" class="btn btn-sm">Export</button>
      </div>
      <div class="page-selection">
        <div class="page-size-selection">
          Page size:
          <input type="number" min="1" v-model="page_size" @input="getCookies();">
        </div>
        <div class="page-number-selection">
          <input type="number" min="1" v-model="page_number" @input="getCookies();"> / {{ page_max }}
        </div>            
      </div>
    </div>
    <p class="description" style="font-style: italic">Note: Click on a value in a cell to copy it to clipboard. Ticked cookies will be copy as JavaScript code to your clipboard when you click <b>Copy</b> button, allowing you to inject them into your browser. <b>Search</b> button will show searchbar for every column.</p>
    <br><br>
    <div class="tableFixHead">
      <table class="table table-hover">
        <thead>
          <tr>
            <th scope="col"><input id="main-checkbox" type="checkbox" @click="toggleCookiesSelection" :checked="allChecked"></th>
            <th class="text_column" scope="col">
              <span>
                Computer
                <div>
                  <input type="text" placeholder="Search text" v-model="computer_search_value" @change="resetPageInfo(); getCookies();">
                </div>
              </span>
            </th>
            <th class="text_column" scope="col">
              <span>
                Windows User2
                <div>
                  <input type="text" placeholder="Search text" v-model="windows_user_search_value" @change="resetPageInfo(); getCookies();">
                </div>
              </span>
            </th>
            <th class="text_column" scope="col">
              <span>
                Cookie name
                <div>
                  <input type="text" placeholder="Search text" v-model="cookie_name_search_value" @input="resetPageInfo(); getCookies();">
                </div>
              </span>
            </th>
            <th class="text_column" scope="col">
              <span>
                Cookie value
                <div>
                  <input type="text" placeholder="Search text" v-model="cookie_value_search_value" @input="resetPageInfo(); getCookies();">
                </div>
              </span>
            </th>
            <th class="text_column" scope="col">
              <span>
                URL
                <div>
                  <input type="text" placeholder="Search text" v-model="url_search_value" @input="resetPageInfo(); getCookies();">
                </div>
              </span>
            </th>
            <th class="text_column" scope="col">
              <span>
                Creation date
                <div>
                  <input type="text" placeholder="Search text" v-model="creation_date_search_value" @input="resetPageInfo(); getCookies();">
                </div>
              </span>
            </th>
            <th class="text_column" scope="col">
              <span>
                Status
              </span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(cookie, index) in cookies" :key="index">
            <td><input class="item-checkbox" :id="index" type="checkbox" @click="clickCookiesCheckbox"></td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(cookie.hostname)">{{ cookie.hostname }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(cookie.windows_user)">{{ cookie.windows_user }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(cookie.cookie_name)">
              <span v-if="cookie.cookie_name != null" class="fullValue" @mouseover="showFullCookieName[index] = true" @mouseleave="showFullCookieName[index] = false">
                {{ cookie.cookie_name.length > 20 ? cookie.cookie_name.substring(0,20)+".." : cookie.cookie_name }}
                <div :id="'cookie_name_' + index" v-show="showFullCookieName[index]">
                  {{cookie.cookie_name}}
                </div>
              </span>
            </td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(cookie.cookie_value)">
              <span v-if="cookie.cookie_value != null" class="fullValue" @mouseover="showFullCookieValue[index] = true" @mouseleave="showFullCookieValue[index] = false">
                {{ cookie.cookie_value.length > 20 ? hideSecretsOnRender(cookie.cookie_value).substring(0,20)+".." : hideSecretsOnRender(cookie.cookie_value) }}
                <div :id="'cookie_value_' + index" v-show="showFullCookieValue[index]">
                  {{cookie.cookie_value}}
                </div>
              </span>
            </td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(cookie.url)">{{ cookie.url }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(cookie.creation_utc)">{{ formatDate(cookie.creation_utc) }}</td>
            <td :class="{ 'expired': isCookieExpired(cookie.expires_utc) }">
              {{ isCookieExpired(cookie.expires_utc) ? 'Expired' : 'Active' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import {config} from '../config';
import { 
  copyToClipBoard, 
  arrayToCsv, 
  downloadBlob,
  clickCheckbox,
  toggleSelection,
} from '../utils';

export default {
  data() {
    return {
      cookies: [],
      showFullCookieName: [],
      showFullCookieValue: [],
      search_boxes: false,
      cookie_name_search_value: '',
      computer_search_value: '',
      cookie_value_search_value: '',
      windows_user_search_value: '',
      url_search_value: '',
      creation_date_search_value: '',
      cookieSelected: 0,
      page_size: 100,
      page_number: 1,
      page_max: 1,
      allChecked: false,
      hideSecrets: false,
    };
  },
  methods: {
    hideSecretsOnRender(data){
      if (this.hideSecrets) {
        return data.replace(/./g, "*")
      }
      return data
    },
    formatDate(dateString) {
      if (!dateString) return '';
      const creationTimestamp = Math.floor(parseInt(dateString) / 1000);
      const date = new Date(creationTimestamp);
      if (isNaN(date.getTime())) return dateString;
      return date.toLocaleString('de-DE', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      });
    },
    isCookieExpired(expiresUtc) {
      if (!expiresUtc) return true;
      const now = new Date();
      const expires = new Date(expiresUtc);
      return now > expires;
    },
    copyItemToClipBoard(data){
      copyToClipBoard(this, data);
    },
    clickCookiesCheckbox(){
      clickCheckbox(this);
    },
    toggleCookiesSelection(){
      toggleSelection(this);
    },
    exportCookiesToCsv(){
      console.log('Export cookies to CSV');
      var cookiesCheckboxes = document.getElementsByClassName("item-checkbox");
      var cookiesToExport = [];
      for (var i=0; i<cookiesCheckboxes.length; i++) {
        if (cookiesCheckboxes[i].checked) {
          const cookie = {...this.cookies[i]};
          Object.keys(cookie).forEach(key => {
            if (cookie[key] !== null && cookie[key] !== undefined) {
              cookie[key] = String(cookie[key]);
            }
          });
          cookiesToExport.push(cookie);
        }
      }
      const dataToExport = arrayToCsv(cookiesToExport);
      downloadBlob(dataToExport, 'cookies_export_' + Date.now()  + '.csv');
    },
    copyCookies() {
      console.log('Copy cookies');
      var fullTextToClipboard = '';
      var cookiesCheckboxes = document.getElementsByClassName("item-checkbox");
      for (var i=0; i<cookiesCheckboxes.length; i++) {
        if (cookiesCheckboxes[i].checked) {
          let cookieName = document.getElementById("cookie_name_"+i);
          let cookieValue = document.getElementById("cookie_value_"+i);
          fullTextToClipboard += "document.cookie='" + cookieName.innerText + "=" + cookieValue.innerText + "'\n";
        }
      }
      copyToClipBoard(this, fullTextToClipboard, "cookies as JavaScript code")
    },
    resetPageInfo() {
      this.page_number = 1;
    },
    getCookies() {
      var path = config.apiPath + '/api/cookies?';
      path += 'page=' + (this.page_number -1) + '&';
      path += 'page_size=' + this.page_size + '&';
      path += 'computer_hostname=' + this.computer_search_value + '&';
      path += 'cookie_name=' + this.cookie_name_search_value + '&';
      path += 'cookie_value=' + this.cookie_value_search_value + '&';
      path += 'windows_user=' + this.windows_user_search_value + '&';
      path += 'url=' + this.url_search_value + '&';
      path += 'creation_date=' + this.creation_date_search_value + '&';
      axios.get(path)
        .then((res) => {
          this.cookies = res.data.cookies;
          console.log(res.data.count);
          console.log(this.page_size);
          this.page_max = Math.ceil(res.data.count/this.page_size); 
          this.showFullCookieName[0] = false; //need to init
          this.showFullCookieValue[0] = false; //need to init
        })
        .catch((error) => {
            console.error(error);
        });
    },
  },
  created() {
    this.getCookies();
  }
};
</script>

<style lang="scss">
.text_column {
  min-width: 8rem;
  max-width: none;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.expired {
  color: #dc3545;
  font-weight: bold;
}

tr {
  border-color: #ddd !important;
}

td {
  cursor: pointer; 
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 8rem;
}

.buttons {
  height: 5rem;
}

.fullValue {
  position: relative;
  display: inline-block;
}

.fullValue div {
  position: absolute;
  z-index: 1;
  background-color: var(--dark);
  color: var(--light);
  padding: 0.5rem;
  border-radius: 0.25rem;
  white-space: nowrap;
  max-width: 20rem;
  overflow: hidden;
  text-overflow: ellipsis;
}

.table {
  width: 100% !important;
  table-layout: fixed;
}

.tableFixHead {
  overflow-x: auto;
  overflow-y: auto;
  max-height: 70vh;
  width: 100%;
}

.container {
  width: 100%;
  padding: 1rem;
}
</style>