<x-app-layout>
    <div class="space-y-8">
        <div>
          <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />
        </div>

        <div class="grid xl:grid-cols-2 grid-cols-1 gap-5">

            <!-- BEGIN: Basic Table -->
            <div class="card">
                <header class=" card-header noborder">
                    <h4 class="card-title">Basic Table
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="overflow-x-auto -mx-6">
                        <div class="inline-block min-w-full align-middle">
                            <div class="overflow-hidden ">
                                <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                    <thead class=" border-t border-slate-100 dark:border-slate-800">
                                        <tr>
                                            <th scope="col" class=" table-th ">
                                               AGE
                                            </th>
                                            <th scope="col" class=" table-th ">
                                               FIRST NAME
                                            </th>
                                            <th scope="col" class=" table-th ">
                                               EMAIL
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                                        @foreach ($tableData as $item)
                                            <tr>
                                                <td class="table-td">{{ $item['age'] }}</td>
                                                <td class="table-td">{{ $item['first_name'] }}</td>
                                                <td class="table-td ">{{ $item['email'] }}</td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Basic Table -->


            <!-- BEGIN: Table Header -->
            <div class="card">
                <header class=" card-header noborder">
                    <h4 class="card-title">Table Head
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="overflow-x-auto -mx-6">
                        <div class="inline-block min-w-full align-middle">
                            <div class="overflow-hidden ">
                                <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                    <thead class="bg-slate-200 dark:bg-slate-700">
                                        <tr>
                                            <th scope="col" class=" table-th ">
                                               AGE
                                            </th>
                                            <th scope="col" class=" table-th ">
                                               FIRST NAME
                                            </th>
                                            <th scope="col" class=" table-th ">
                                               EMAIL
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                                        @foreach ($tableData as $item)
                                            <tr>
                                                <td class="table-td">{{ $item['age'] }}</td>
                                                <td class="table-td">{{ $item['first_name'] }}</td>
                                                <td class="table-td ">{{ $item['email'] }}</td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Table Header -->


            <!-- BEGIN: Bordered Table -->
            <div class="card">
                <header class=" card-header noborder">
                    <h4 class="card-title">Bordered Table
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="overflow-x-auto ">
                        <div class="inline-block min-w-full align-middle">
                            <div class="overflow-hidden ">
                                <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                    <thead class="">
                                        <tr>
                                            <th scope="col" class=" table-th border border-slate-100 dark:bg-slate-800 dark:border-slate-700">
                                               AGE
                                            </th>
                                            <th scope="col" class=" table-th border border-slate-100 dark:bg-slate-800 dark:border-slate-700">
                                               FIRST NAME
                                            </th>
                                            <th scope="col" class=" table-th border border-slate-100 dark:bg-slate-800 dark:border-slate-700">
                                               EMAIL
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                                        @foreach ($tableData as $item)
                                            <tr>
                                                <td class="table-td border border-slate-100 dark:bg-slate-800 dark:border-slate-700">{{ $item['age'] }}</td>
                                                <td class="table-td border border-slate-100 dark:bg-slate-800 dark:border-slate-700">{{ $item['first_name'] }}</td>
                                                <td class="table-td border border-slate-100 dark:bg-slate-800 dark:border-slate-700">{{ $item['email'] }}</td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Bordered Table -->


            <!-- BEGIN: Borderless Table -->
            <div class="card">
                <header class=" card-header noborder">
                    <h4 class="card-title">Borderless Table
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="overflow-x-auto ">
                        <div class="inline-block min-w-full align-middle">
                            <div class="overflow-hidden ">
                                <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                    <thead class="">
                                        <tr>
                                            <th scope="col" class=" table-th ">
                                                AGE
                                            </th>
                                            <th scope="col" class=" table-th ">
                                                FIRST NAME
                                            </th>
                                            <th scope="col" class=" table-th ">
                                                EMAIL
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white dark:bg-slate-800 ">
                                        @foreach ($tableData as $item)
                                            <tr>
                                                <td class="table-td ">{{ $item['age'] }}</td>
                                                <td class="table-td ">{{ $item['first_name'] }}</td>
                                                <td class="table-td  ">{{ $item['email'] }}</td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Borderless Table -->


            <!-- BEGIN: Striped Tables -->
            <div class="card">
                <header class=" card-header noborder">
                    <h4 class="card-title">Striped Rows
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="overflow-x-auto -mx-6">
                        <div class="inline-block min-w-full align-middle">
                            <div class="overflow-hidden ">
                                <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                    <thead class="bg-slate-200 dark:bg-slate-700">
                                        <tr>
                                            <th scope="col" class=" table-th ">
                                                ID
                                            </th>
                                            <th scope="col" class=" table-th ">
                                                First name
                                            </th>
                                            <th scope="col" class=" table-th ">
                                                Email
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                                        @foreach ($tableData as $item)
                                            <tr class="even:bg-slate-50 dark:even:bg-slate-700">
                                            <td class="table-td">{{ $item['age'] }}</td>
                                            <td class="table-td">{{ $item['first_name'] }}</td>
                                            <td class="table-td ">{{ $item['email'] }}</td>
                                       @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Striped Tables -->

            <!-- BEGIN: Hover Tables -->
            <div class="card">
                <header class=" card-header noborder">
                    <h4 class="card-title">Hover Table
                    </h4>
                </header>
                <div class="card-body px-6 pb-6">
                    <div class="overflow-x-auto -mx-6">
                        <div class="inline-block min-w-full align-middle">
                            <div class="overflow-hidden ">
                                <table class="min-w-full divide-y divide-slate-100 table-fixed dark:divide-slate-700">
                                    <thead class="bg-slate-200 dark:bg-slate-700">
                                        <tr>
                                            <th scope="col" class=" table-th ">
                                                ID
                                            </th>
                                            <th scope="col" class=" table-th ">
                                                First Name
                                            </th>
                                            <th scope="col" class=" table-th ">
                                                Email
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-slate-100 dark:bg-slate-800 dark:divide-slate-700">
                                        @foreach($tableData as $item)
                                            <tr class="hover:bg-slate-200 dark:hover:bg-slate-700">
                                                <td class="table-td">{{ $item['age'] }}</td>
                                                <td class="table-td">{{ $item['first_name'] }}</td>
                                                <td class="table-td ">{{ $item['email'] }}</td>
                                            </tr>
                                       @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- END: Hover Tables -->
        </div>
    </div>
</x-app-layout>
