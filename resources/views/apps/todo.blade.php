<x-app-layout>
    <div class="space-y-8">
        {{-- <div>--}}
        {{-- <x-breadcrumb :page-title="$pageTitle" :breadcrumb-items="$breadcrumbItems" />--}}
        {{-- </div>--}}

        <div class="flex md:space-x-5 app_height overflow-hidden relative rtl:space-x-reverse">
            <div class="todo-sidebar ">
                <div class="h-full card">
                    <div class="card-body py-6 h-full flex flex-col">
                        <div class="flex-1 h-full px-6">
                            <button class="btn inline-flex justify-center btn-dark w-full" data-bs-toggle="modal" data-bs-target="#newTodoModal">
                                <span class="flex items-center">
                                    <iconify-icon class="text-xl ltr:mr-2 rtl:ml-2" icon="ph:plus-bold"></iconify-icon>
                                    <span>Add Task</span>
                                </span>
                            </button>
                        </div>
                        <div class="h-full px-6 " data-simplebar="data-simplebar">
                            <ul class="todo-categories list mt-6">
                                <x-todo.topfilter />
                            </ul>
                            <div class="block py-4 text-slate-800 dark:text-slate-400 font-semibold text-xs uppercase">
                                Tags
                            </div>
                            <ul class="todo-categories list">
                                <x-todo.bottomfilter />
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            <div class="todo-overlay"></div>
            <div class="flex-1 md:w-[calc(100%-320px)]">
                <div class="h-full card">
                    <div class="p-0  h-full relative card-body">
                        <x-todo.header />
                        <div class="h-full all-todos overflow-x-hidden" data-simplebar="data-simplebar">
                            <ul class="divide-y divide-slate-100 dark:divide-slate-700 -mb-6 h-full todo-list">
                                <x-todo.todos />
                                <x-todo.no-result />
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="newTodoModal" tabindex="-1" aria-labelledby="newTodoModalLabel" aria-hidden="true">
            <div class="modal-dialog relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col lg:w-[576px] w-full pointer-events-auto bg-white bg-clip-padding
                                                rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                Add Task
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center
                                                            dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <form class="flex flex-col space-y-3">
                                <div class="input-area">
                                    <label for="title" class="form-label">Title</label>
                                    <input id="title" type="text" class="form-control" placeholder="Enter Title">
                                </div>
                                <div>
                                    <label for="assigned" class="form-label">Assignee</label>
                                    <select name="assigned" id="assigneds" class="form-control w-full mt-2 py-2">
                                        <option value="option1" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 1</option>
                                        <option value="option2" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 2</option>
                                        <option value="option3" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 3</option>
                                    </select>
                                </div>
                                <div>
                                    <label for="default-picker" class=" form-label">Default Functionality</label>
                                    <input class="form-control py-2 flatpickr flatpickr-input active" id="default-picker" value="" type="text" readonly="readonly">
                                </div>
                                <div>
                                    <label for="tags" class="form-label">Tag</label>
                                    <select name="tags" id="tagss" class="form-control w-full mt-2 py-2">
                                        <option value="option1" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 1</option>
                                        <option value="option2" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 2</option>
                                        <option value="option3" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 3</option>
                                    </select>
                                </div>
                                <div class="input-area">
                                    <label for="textarea" class="form-label">Description</label>
                                    <textarea name="textarea" id="textarea" rows="3" class="form-control" placeholder="Enter Title"></textarea>
                                </div>
                                <div class="flex items-center justify-end rounded-b dark:border-slate-600">
                                    <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Submit</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade fixed top-0 left-0 hidden w-full h-full outline-none overflow-x-hidden overflow-y-auto" id="editTodoModal" tabindex="-1" aria-labelledby="editTodoModalLabel" aria-hidden="true">
            <div class="modal-dialog relative w-auto pointer-events-none">
                <div class="modal-content border-none shadow-lg relative flex flex-col lg:w-[576px] w-full pointer-events-auto bg-white bg-clip-padding rounded-md outline-none text-current">
                    <div class="relative bg-white rounded-lg shadow dark:bg-slate-700">
                        <!-- Modal header -->
                        <div class="flex items-center justify-between p-5 border-b rounded-t dark:border-slate-600 bg-black-500">
                            <h3 class="text-base font-medium text-white dark:text-white capitalize">
                                Edit Task
                            </h3>
                            <button type="button" class="text-slate-400 bg-transparent hover:text-slate-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-slate-600 dark:hover:text-white" data-bs-dismiss="modal">
                                <svg aria-hidden="true" class="w-5 h-5" fill="#ffffff" viewbox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                                <span class="sr-only">Close modal</span>
                            </button>
                        </div>
                        <!-- Modal body -->
                        <div class="p-6 space-y-4">
                            <form class="flex flex-col space-y-3">
                                <div class="input-area">
                                    <label for="title" class="form-label">Title</label>
                                    <input id="title" type="text" class="form-control" value="Task 01" placeholder="Enter Title">
                                </div>
                                <div>
                                    <label for="assigned" class="form-label">Assignee</label>
                                    <select name="assigned" id="assigneds" class="form-control w-full mt-2 py-2">
                                        <option value="option1" selected class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 1</option>
                                        <option value="option2" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 2</option>
                                        <option value="option3" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 3</option>
                                    </select>
                                </div>
                                <div>
                                    <label for="default-picker" class=" form-label">Default Functionality</label>
                                    <input class="form-control py-2 flatpickr flatpickr-input active" id="default-picker" value="" type="text" readonly="readonly">
                                </div>
                                <div>
                                    <label for="tags" class="form-label">Tag</label>
                                    <select name="tags" id="tagss" class="form-control w-full mt-2 py-2">
                                        <option value="option1" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 1</option>
                                        <option value="option2" selected class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 2</option>
                                        <option value="option3" class=" inline-block font-Inter font-normal text-sm text-slate-600">Option 3</option>
                                    </select>
                                </div>
                                <div class="input-area">
                                    <label for="textarea" class="form-label">Description</label>
                                    <textarea name="textarea" id="textarea" rows="3" class="form-control" value="Lorem ipsum dolor sit amet." placeholder="Enter Title">
                                    </textarea>
                                </div>
                                <div class="flex items-center justify-end rounded-b dark:border-slate-600">
                                    <button data-bs-dismiss="modal" class="btn inline-flex justify-center text-white bg-black-500">Submit</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    @push('scripts')
        @vite(['resources/js/custom/app-todo.js'])
    @endpush
</x-app-layout>
