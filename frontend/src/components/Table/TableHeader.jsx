import { IconChevronDown, IconChevronUp } from "@tabler/icons-react";
import cn from "clsx";

function TableHeader(props) {
	const { tableInstance } = props;
	const headerGroups = tableInstance.getHeaderGroups();

	return (
		<thead>
			{headerGroups.map((headerGroup) => (
				<tr key={headerGroup.id}>
					{headerGroup.headers.map((header) => {
						const { column } = header;
						const { className } = column.columnDef.meta ?? {};
						const sorted = column.getIsSorted();
						const canSort = column.getCanSort();
						return (
							<th
								key={header.id}
								className={cn(className, canSort && "cursor-pointer")}
								aria-sort={
									sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined
								}
								onClick={column.getToggleSortingHandler()}
							>
								<span className="d-inline-flex align-items-center gap-1">
									{typeof column.columnDef.header === "string" ? `${column.columnDef.header}` : null}
									{sorted === "asc" ? <IconChevronUp size={14} /> : null}
									{sorted === "desc" ? <IconChevronDown size={14} /> : null}
								</span>
							</th>
						);
					})}
				</tr>
			))}
		</thead>
	);
}

export { TableHeader };
