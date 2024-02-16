from cato_services.pipeline.ci_pipeline import CIPipeline, ImageScanResult, ImageScanPipelineStep
from cato_services.util import utils
from .image_scan_summary import image_data_to_template_params, SUMMARY_TEMPLATE

def write_output_to_summary_markdown(output):
    pass

class GithubWorkflow(CIPipeline):
    def output_step(self):
        return super().output_step()
    
    def output_summary(self):
        return super().output_summary()
    
class GithubActionsImageScanStep(ImageScanPipelineStep):
    def output_image_scan_summary(self, scan_result: ImageScanResult):
        template_params = image_data_to_template_params(scan_result)
        summary_table_output = utils.build_string_from_template(SUMMARY_TEMPLATE, template_params)
        write_output_to_summary_markdown(summary_table_output)