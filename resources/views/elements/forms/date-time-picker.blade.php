<x-app-layout>
  <div class="space-y-8">
    <div>
      <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
    </div>

    <div class="card rounded-md bg-white dark:bg-slate-800 lg:h-full shadow-base">
      <div class="card-body flex flex-col p-6">
        <header class="flex mb-5 items-center border-b border-slate-100 dark:border-slate-700 pb-5 -mx-6 px-6">
          <div class="flex-1">
            <div class="card-title text-slate-900 dark:text-white">Date & Time Picker</div>
          </div>
        </header>
        <div class="grid md:grid-cols-2 grid-cols-1 gap-6">
          <div>
            <label for="default-picker" class=" form-label">Default Functionality</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="default-picker" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="time-date-picker" class="form-label">Date & Time</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="time-date-picker" data-enable-time="true" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="range-picker" class="form-label">Range</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="range-picker" data-mode="range" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="disabled-range-picker" class="form-label">Disabled Range</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="disabled-range-picker" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="time-picker" class="form-label">Basic 24hrs</label>
            <input class="form-control py-2 flatpickr time flatpickr-input active" id="time-picker" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="multipleDate-picker" class="form-label">Multiple Dates</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="multipleDate-picker" data-mode="multiple" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="humanFriendly_picker" class="form-label">Human Friendly</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="humanFriendly_picker" value="" type="text" readonly="readonly">
          </div>

          <div>
            <label for="inline_picker" class="form-label">Inline</label>
            <input class="form-control py-2 flatpickr flatpickr-input active" id="inline_picker" value="" type="text" readonly="readonly">
          </div>

        </div>
      </div>
    </div>
  </div>


  @push('scripts')
  @vite(['resources/js/plugins/flatpickr.js'])
  <script type="module">
    // flatpickr
    $(".flatpickr").flatpickr({
      dateFormat: "Y-m-d",
      defaultDate: "today",
    });
    // flatpickr
    $("#disabled-range-picker").flatpickr({
      mode: "range",
      minDate: "today",
      dateFormat: "Y-m-d",
      disable: [
        function(date) {
          // disable every multiple of 8
          return !(date.getDate() % 8);
        },
      ],
    });

    $(".flatpickr.time").flatpickr({
      enableTime: true,
      noCalendar: true,
      dateFormat: "H:i",
      time_24hr: true,
    });

    $("#humanFriendly_picker").flatpickr({
      altInput: true,
      altFormat: "F j, Y",
      dateFormat: "Y-m-d",
    });

    $("#inline_picker").flatpickr({
      inline: true,
      altInput: true,
      altFormat: "F j, Y",
      dateFormat: "Y-m-d",
    });
  </script>
  @endpush
</x-app-layout>