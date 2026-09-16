import { T } from "src/locale";

function EmptyRow({ tableInstance }) {
	return (
		<tr>
			<td colSpan={tableInstance.getAllFlatColumns().length}>
				<p className="text-center">
					<T id="table.no-items" />
				</p>
			</td>
		</tr>
	);
}

export { EmptyRow };
