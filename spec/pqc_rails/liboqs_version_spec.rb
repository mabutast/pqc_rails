# frozen_string_literal: true

RSpec.describe "PqcRails.liboqs_version" do
  it "読み込んだliboqsの版を返す" do
    expect(PqcRails.liboqs_version).to match(/\A\d+\.\d+\.\d+/)
  end

  it "rails pqc_rails:statusのliboqsの行に版を含める" do
    liboqs = PqcRails::StatusCheck.run.find { |result| result.name == "liboqs" }

    expect(liboqs.detail).to include(PqcRails.liboqs_version)
  end
end
