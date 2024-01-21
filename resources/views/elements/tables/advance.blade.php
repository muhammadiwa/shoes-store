<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class=" space-y-5">
            <div class="card">
              <header class=" card-header noborder">
                <h4 class="card-title">Advanced Table
                </h4>
              </header>
              <div class="card-body px-6 pb-6">
                <div class="overflow-x-auto -mx-6 dashcode-data-table">
                  <span class=" col-span-8  hidden"></span>
                  <span class="  col-span-4 hidden"></span>
                  <div class="inline-block min-w-full align-middle">
                    <div class="overflow-hidden ">
                      <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700" id="data-table">
                        <thead class=" border-t border-slate-100 dark:border-slate-800">
                          <tr>
                              <th scope="col" class=" table-th ">
                                ID
                              </th>
                              <th scope="col" class=" table-th ">
                                Order
                              </th>
                              <th scope="col" class=" table-th ">
                                Customer
                              </th>
                              <th scope="col" class=" table-th ">
                                Date
                              </th>
                              <th scope="col" class=" table-th ">
                                Quanatity
                              </th>
                              <th scope="col" class=" table-th ">
                                Amount
                              </th>
                              <th scope="col" class=" table-th ">
                                Status
                              </th>
                              <th scope="col" class=" table-th ">
                                Action
                              </th>
                          </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                            @foreach($tableData as $item)
                            <tr>
                              <td class="table-td">{{ $item['id'] }}</td>
                              <td class="table-td ">#{{ $item['order'] }}</td>
                              <td class="table-td">
                                <span class="flex">
                                  <span class="w-7 h-7 rounded-full ltr:mr-3 rtl:ml-3 flex-none">
                                    <img src="images/all-img/{{ $item['customer']['image'] }}" alt="{{ $item['id'] }}" class="object-cover w-full h-full rounded-full">
                                  </span>
                                  <span class="text-sm text-slate-600 dark:text-slate-300 capitalize">{{ $item['customer']['name'] }}</span>
                                </span>
                              </td>
                              <td class="table-td ">{{ $item['date'] }}</td>
                              <td class="table-td ">
                                <div>
                                  {{ $item['quantity'] }}
                                </div>
                              </td>
                              <td class="table-td ">
                                <div>
                                  {{ $item['amount'] }}
                                </div>
                              </td>
                              <td class="table-td ">
                                @if($item['status'] == 'paid')
                                  <div class="inline-block px-3 min-w-[90px] text-center mx-auto py-1 rounded-[999px] bg-opacity-25 text-success-500
                                      bg-success-500">
                                    {{ $item['status'] }}
                                  </div>
                                @elseif($item['status'] == 'due')
                                  <div class="inline-block px-3 min-w-[90px] text-center mx-auto py-1 rounded-[999px] bg-opacity-25 text-warning-500
                                      bg-warning-500">
                                    {{ $item['status'] }}
                                  </div>
                                @elseif($item['status'] == 'cancled')
                                  <div class="inline-block px-3 min-w-[90px] text-center mx-auto py-1 rounded-[999px] bg-opacity-25 text-danger-500
                                      bg-danger-500">
                                    {{ $item['status'] }}
                                  </div>
                                @endif
                              </td>
                              <td class="table-td ">
                                <div>
                                  <div class="relative">
                                    <div class="dropdown relative">
                                      <button
                                        class="text-xl text-center block w-full "
                                        type="button"
                                        id="tableDropdownMenuButton{{$item['id']}}"
                                        data-bs-toggle="dropdown"
                                        aria-expanded="false">
                                        <iconify-icon icon="heroicons-outline:dots-vertical"></iconify-icon>
                                      </button>
                                      <ul class=" dropdown-menu min-w-[120px] absolute text-sm text-slate-700 dark:text-white hidden bg-white dark:bg-slate-700
                                          shadow z-[2] float-left overflow-hidden list-none text-left rounded-lg mt-1 m-0 bg-clip-padding border-none">
                                        <li>
                                          <a
                                            href="#"
                                            class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                              dark:hover:text-white">
                                            View</a>
                                        </li>
                                        <li>
                                          <a
                                            href="#"
                                            class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                              dark:hover:text-white">
                                            Edit</a>
                                        </li>
                                        <li>
                                          <a
                                            href="#"
                                            class="text-slate-600 dark:text-white block font-Inter font-normal px-4 py-2 hover:bg-slate-100 dark:hover:bg-slate-600
                                              dark:hover:text-white">
                                            Delete</a>
                                        </li>
                                      </ul>
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          @endforeach
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            </div>


            <div class="card">
              <header class=" card-header noborder">
                <h4 class="card-title">Advanced Table Two
                </h4>
              </header>
              <div class="card-body px-6 pb-6">
                <div class="overflow-x-auto -mx-6 dashcode-data-table">
                  <span class=" col-span-8  hidden"></span>
                  <span class="  col-span-4 hidden"></span>
                  <div class="inline-block min-w-full align-middle">
                    <div class="overflow-hidden ">
                      <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700 data-table">
                        <thead class=" bg-slate-200 dark:bg-slate-700">
                          <tr>
                              <th scope="col" class=" table-th ">
                                Id
                              </th>
                              <th scope="col" class=" table-th ">
                                Order
                              </th>
                              <th scope="col" class=" table-th ">
                                Customer
                              </th>
                              <th scope="col" class=" table-th ">
                                Date
                              </th>
                              <th scope="col" class=" table-th ">
                                Quantity
                              </th>
                              <th scope="col" class=" table-th ">
                                Amount
                              </th>
                              <th scope="col" class=" table-th ">
                                Status
                              </th>
                              <th scope="col" class=" table-th ">
                                Action
                              </th>
                          </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                            @foreach($tableData as $item)
                            <tr>
                              <td class="table-td">{{ $item['id'] }}</td>
                              <td class="table-td ">#{{ $item['order'] }}</td>
                              <td class="table-td">
                                <span class="flex">
                                  <span class="w-7 h-7 rounded-full ltr:mr-3 rtl:ml-3 flex-none">
                                    <img src="images/all-img/{{ $item['customer']['image'] }}" alt="{{ $item['id'] }}" class="object-cover w-full h-full rounded-full">
                                  </span>
                                  <span class="text-sm text-slate-600 dark:text-slate-300 capitalize">{{ $item['customer']['name'] }}</span>
                                </span>
                              </td>
                              <td class="table-td ">{{ $item['date'] }}</td>
                              <td class="table-td ">
                                <div>
                                  {{ $item['quantity'] }}
                                </div>
                              </td>
                              <td class="table-td ">
                                <div>
                                  {{ $item['amount'] }}
                                </div>
                              </td>
                              <td class="table-td ">
                                @if($item['status'] == "paid")
                                  <div class="inline-block px-3 min-w-[90px] text-center mx-auto py-1 rounded-[999px] bg-opacity-25 text-success-500
                                      bg-success-500">
                                    {{ $item['status'] }}
                                  </div>
                                @elseif($item['status'] == "due")
                                  <div class="inline-block px-3 min-w-[90px] text-center mx-auto py-1 rounded-[999px] bg-opacity-25 text-warning-500
                                      bg-warning-500">
                                    {{ $item['status'] }}
                                  </div>
                                @else
                                  <div class="inline-block px-3 min-w-[90px] text-center mx-auto py-1 rounded-[999px] bg-opacity-25 text-danger-500
                                      bg-danger-500">
                                    {{ $item['status'] }}
                                  </div>
                                @endif
                              </td>
                              <td class="table-td ">
                                <div class="flex space-x-3 rtl:space-x-reverse">
                                  <button class="action-btn" type="button">
                                    <iconify-icon icon="heroicons:eye"></iconify-icon>
                                  </button>
                                  <button class="action-btn" type="button">
                                    <iconify-icon icon="heroicons:pencil-square"></iconify-icon>
                                  </button>
                                  <button class="action-btn" type="button">
                                    <iconify-icon icon="heroicons:trash"></iconify-icon>
                                  </button>
                                </div>
                              </td>
                            </tr>
                            @endforeach
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            </div>
        </div>
    </div>


    @push('scripts')
        <script type="module">
            // data table validation
            $("#data-table, .data-table").DataTable({
                dom: "<'grid grid-cols-12 gap-5 px-6 mt-6'<'col-span-4'l><'col-span-8 flex justify-end'f><'#pagination.flex items-center'>><'min-w-full't><'flex justify-end items-center'p>",
                paging: true,
                ordering: true,
                info: false,
                searching: true,
                lengthChange: true,
                lengthMenu: [10, 25, 50, 100],
                language: {
                    lengthMenu: "Show _MENU_ entries",
                    paginate: {
                        previous: `<iconify-icon icon="ic:round-keyboard-arrow-left"></iconify-icon>`,
                        next: `<iconify-icon icon="ic:round-keyboard-arrow-right"></iconify-icon>`,
                    },
                    search: "Search:",
                },
            });
        </script>
    @endpush
</x-app-layout>
