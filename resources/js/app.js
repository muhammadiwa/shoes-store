import "./bootstrap";
// Core Js
import jQuery from "jquery";
window.$ = jQuery;
window.jQuery = jQuery;

import "tw-elements";

import SimpleBar from "simplebar";
window.SimpleBar = SimpleBar;
import "simplebar/dist/simplebar.css";

// animate css
import "animate.css";

// You will need a ResizeObserver polyfill for browsers that don't support it! (iOS Safari, Edge, ...)
import ResizeObserver from "resize-observer-polyfill";
window.ResizeObserver = ResizeObserver;

import leaflet from "leaflet";
window.leaflet = leaflet;

import { Calendar } from "@fullcalendar/core";
import dayGridPlugin from "@fullcalendar/daygrid";
import timeGridPlugin from "@fullcalendar/timegrid";
import listPlugin from "@fullcalendar/list";
window.Calendar = Calendar;
window.dayGridPlugin = dayGridPlugin;
window.timeGridPlugin = timeGridPlugin;
window.listPlugin = listPlugin;

import Cleave from "cleave.js";
window.Cleave = Cleave;

import * as Chart from "chart.js";
window.Chart = Chart;
import ApexCharts from "apexcharts";
window.ApexCharts = ApexCharts;

import "country-select-js";

// Drag and Drop for kenban
import dragula from "dragula/dist/dragula";
import "dragula/dist/dragula.css";
window.dragula = dragula;

// Icon
import "iconify-icon";

// SweetAlert
import Swal from "sweetalert2";
window.Swal = Swal;

// tooltip and popover
import tippy from "tippy.js";
import "tippy.js/dist/tippy.css";
window.tippy = tippy;


// DATA-TABLE
import DataTable from "datatables.net-dt";
window.DataTable = DataTable;

// OWL CAROUSEL
// import 'owl.carousel/dist/assets/owl.carousel.css';
// import 'owl.carousel';
import cleave from 'cleave.js'
window.cleave = cleave;

// jQuery validation
import validate from "jquery-validation";
window.validate = validate;

import.meta.glob(["../images/**"]);
