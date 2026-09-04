import { T } from "src/locale";
import styles from "./LoadingSkeleton.module.css";

const skeletonItems = [0, 1, 2, 3];
const skeletonRows = [0, 1, 2, 3, 4];

const LoadingStatus = () => (
	<span className="visually-hidden" role="status">
		<T id="loading" />
	</span>
);

const MetricSkeletons = () => (
	<div className="row g-3 mb-4" aria-hidden="true">
		{skeletonItems.map((item) => (
			<div className="col-sm-6 col-xl-3" key={item}>
				<div className="card card-sm h-100">
					<div className="card-body d-grid gap-3">
						<div className={`${styles.block} ${styles.label}`} />
						<div className={`${styles.block} ${styles.value}`} />
						<div className={`${styles.block} ${styles.hint}`} />
					</div>
				</div>
			</div>
		))}
	</div>
);

export const OverviewSkeleton = () => (
	<div aria-busy="true">
		<LoadingStatus />
		<MetricSkeletons />
		<div className="row g-4" aria-hidden="true">
			<div className="col-lg-7">
				<div className={`${styles.block} ${styles.chart}`} />
			</div>
			<div className="col-lg-5">
				<div className={`${styles.block} ${styles.chart}`} />
			</div>
		</div>
	</div>
);

export const MetricsSkeleton = () => (
	<div aria-busy="true">
		<LoadingStatus />
		<MetricSkeletons />
	</div>
);

export const TableSkeleton = () => (
	<div className="d-grid gap-2" aria-busy="true">
		<LoadingStatus />
		<div aria-hidden="true" className="d-grid gap-2">
			{skeletonRows.map((row) => (
				<div className={`${styles.block} ${styles.row}`} key={row} />
			))}
		</div>
	</div>
);
